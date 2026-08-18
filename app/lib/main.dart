import 'dart:io';

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
// ignore: implementation_imports, invalid_use_of_internal_member
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show PlatformInt64, PlatformInt64Util;
import 'package:path_provider/path_provider.dart';
import 'package:app/src/rust/api/contacts.dart';
import 'package:app/src/rust/api/identity.dart';
import 'package:app/src/rust/api/invite.dart';
import 'package:app/src/rust/frb_generated.dart';

/// Where the passphrase-sealed identity lives on this device. Plain filesystem storage for
/// native targets; web has no equivalent yet (see `_LatticeAppState` below).
Future<String> _vaultPath() async {
  final dir = await getApplicationSupportDirectory();
  return '${dir.path}/identity.vault';
}

/// Where the passphrase-sealed trust graph (contacts) lives, alongside the identity vault.
Future<String> _contactsVaultPath() async {
  final dir = await getApplicationSupportDirectory();
  return '${dir.path}/contacts.vault';
}

/// `core`'s timestamps are Unix *seconds* throughout (see e.g. `trust::TrustGraph`); Dart's
/// clock is milliseconds, so every call site converts here rather than risk a stray 1000x
/// mismatch reaching the FFI boundary. Returns `PlatformInt64` (an `int` natively, a `BigInt`
/// on web — `PlatformInt64Util.from` is the portable way to build one from a plain `int`,
/// the same helper the generated bindings themselves use).
PlatformInt64 _nowUnixSeconds() => PlatformInt64Util.from(DateTime.now().millisecondsSinceEpoch ~/ 1000);

Future<void> main() async {
  await RustLib.init();
  runApp(const LatticeApp());
}

class LatticeApp extends StatefulWidget {
  const LatticeApp({super.key});

  @override
  State<LatticeApp> createState() => _LatticeAppState();
}

class _LatticeAppState extends State<LatticeApp> {
  late Future<String?> _existingVaultPath;

  @override
  void initState() {
    super.initState();
    _existingVaultPath = _findExistingVault();
  }

  Future<String?> _findExistingVault() async {
    // path_provider (and File I/O generally) isn't meaningful on web; treat as always-fresh
    // there rather than fail. Native persistence is what's actually verified end to end.
    if (kIsWeb) return null;
    final path = await _vaultPath();
    return File(path).existsSync() ? path : null;
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'lattice',
      theme: ThemeData(colorSchemeSeed: Colors.deepPurple, useMaterial3: true),
      home: FutureBuilder<String?>(
        future: _existingVaultPath,
        builder: (context, snapshot) {
          if (!snapshot.hasData && snapshot.connectionState != ConnectionState.done) {
            return const Scaffold(body: Center(child: CircularProgressIndicator()));
          }
          final vaultPath = snapshot.data;
          return vaultPath == null ? const HomeScreen() : UnlockScreen(vaultPath: vaultPath);
        },
      ),
    );
  }
}

/// First real screen: choose to create a fresh identity or restore an existing one. Both
/// paths call straight into `lattice-core` via `flutter_rust_bridge` — no mocked data.
class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('lattice')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text(
                  'A local-first web of trust. No account, no server — your identity '
                  'lives only on this device.',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 32),
                FilledButton(
                  onPressed: () => Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const CreateIdentityScreen()),
                  ),
                  child: const Padding(
                    padding: EdgeInsets.symmetric(vertical: 12),
                    child: Text('Create a new identity'),
                  ),
                ),
                const SizedBox(height: 12),
                OutlinedButton(
                  onPressed: () => Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const RestoreIdentityScreen()),
                  ),
                  child: const Padding(
                    padding: EdgeInsets.symmetric(vertical: 12),
                    child: Text('Restore from recovery phrase'),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class CreateIdentityScreen extends StatefulWidget {
  const CreateIdentityScreen({super.key});

  @override
  State<CreateIdentityScreen> createState() => _CreateIdentityScreenState();
}

class _CreateIdentityScreenState extends State<CreateIdentityScreen> {
  final _nicknameController = TextEditingController();
  IdentitySummary? _created;
  String? _error;

  void _generate() {
    setState(() => _error = null);
    try {
      final summary = createIdentity(
        nickname: _nicknameController.text.trim().isEmpty ? 'me' : _nicknameController.text.trim(),
      );
      setState(() => _created = summary);
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    final created = _created;
    return Scaffold(
      appBar: AppBar(title: const Text('Create identity')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: created == null
                ? Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      TextField(
                        controller: _nicknameController,
                        decoration: const InputDecoration(
                          labelText: 'Nickname (local only, never shared)',
                          border: OutlineInputBorder(),
                        ),
                      ),
                      const SizedBox(height: 16),
                      if (_error != null) ...[
                        Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                        const SizedBox(height: 16),
                      ],
                      FilledButton(onPressed: _generate, child: const Text('Generate identity')),
                    ],
                  )
                : _RecoveryPhraseView(summary: created),
          ),
        ),
      ),
    );
  }
}

/// Shows the newly-generated (or restored) identity's recovery phrase and fingerprint, then
/// hands off to [SetPassphraseScreen] to persist it locally. Real, sensitive secret material
/// from `lattice-core` — treated as such: no clipboard helper, no "share" button, just what's
/// needed to write it down.
class _RecoveryPhraseView extends StatelessWidget {
  const _RecoveryPhraseView({required this.summary});

  final IdentitySummary summary;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Card(
          color: Theme.of(context).colorScheme.errorContainer,
          child: const Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              'Write these 24 words down somewhere safe, offline. Anyone who has them can '
              'restore your identity. lattice never stores or transmits them.',
            ),
          ),
        ),
        const SizedBox(height: 16),
        GridView.count(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          crossAxisCount: 2,
          childAspectRatio: 4,
          children: [
            for (var i = 0; i < summary.recoveryWords.length; i++)
              Text('${i + 1}. ${summary.recoveryWords[i]}'),
          ],
        ),
        const SizedBox(height: 16),
        Text('Nickname: ${summary.nickname}'),
        Text('Fingerprint: ${summary.localIdHex}', style: const TextStyle(fontFamily: 'monospace')),
        const SizedBox(height: 24),
        FilledButton(
          onPressed: () => Navigator.of(context).pushReplacement(
            MaterialPageRoute(builder: (_) => SetPassphraseScreen(summary: summary)),
          ),
          child: const Text("I've written it down"),
        ),
      ],
    );
  }
}

class RestoreIdentityScreen extends StatefulWidget {
  const RestoreIdentityScreen({super.key});

  @override
  State<RestoreIdentityScreen> createState() => _RestoreIdentityScreenState();
}

class _RestoreIdentityScreenState extends State<RestoreIdentityScreen> {
  final _nicknameController = TextEditingController();
  final _phraseController = TextEditingController();
  IdentitySummary? _restored;
  String? _error;

  void _restore() {
    setState(() => _error = null);
    try {
      final summary = restoreIdentity(
        recoveryPhrase: _phraseController.text.trim(),
        nickname: _nicknameController.text.trim().isEmpty ? 'me' : _nicknameController.text.trim(),
      );
      setState(() => _restored = summary);
    } catch (e) {
      setState(() => _error = 'Could not restore from that phrase: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final restored = _restored;
    return Scaffold(
      appBar: AppBar(title: const Text('Restore identity')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: restored == null
                ? Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      TextField(
                        controller: _phraseController,
                        maxLines: 4,
                        decoration: const InputDecoration(
                          labelText: 'Your 24-word recovery phrase',
                          border: OutlineInputBorder(),
                        ),
                      ),
                      const SizedBox(height: 16),
                      TextField(
                        controller: _nicknameController,
                        decoration: const InputDecoration(
                          labelText: 'Nickname for this device (local only)',
                          border: OutlineInputBorder(),
                        ),
                      ),
                      const SizedBox(height: 16),
                      if (_error != null) ...[
                        Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                        const SizedBox(height: 16),
                      ],
                      FilledButton(onPressed: _restore, child: const Text('Restore')),
                    ],
                  )
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const Text('Restored. If this fingerprint matches the one you wrote down, it worked:'),
                      const SizedBox(height: 8),
                      Text(
                        restored.localIdHex,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 16),
                      ),
                      const SizedBox(height: 24),
                      FilledButton(
                        onPressed: () => Navigator.of(context).pushReplacement(
                          MaterialPageRoute(builder: (_) => SetPassphraseScreen(summary: restored)),
                        ),
                        child: const Text('Continue'),
                      ),
                    ],
                  ),
          ),
        ),
      ),
    );
  }
}

/// Sets a local storage passphrase and seals the identity under it (`lattice-core`'s
/// Argon2id/XChaCha20-Poly1305 vault), so the next app launch skips straight to
/// [UnlockScreen] instead of asking to create or restore again. This passphrase protects
/// *this device's copy*; the 24-word phrase already shown is the real backup.
class SetPassphraseScreen extends StatefulWidget {
  const SetPassphraseScreen({super.key, required this.summary});

  final IdentitySummary summary;

  @override
  State<SetPassphraseScreen> createState() => _SetPassphraseScreenState();
}

class _SetPassphraseScreenState extends State<SetPassphraseScreen> {
  final _passphraseController = TextEditingController();
  final _confirmController = TextEditingController();
  String? _error;
  bool _saving = false;

  Future<void> _save() async {
    if (_passphraseController.text.isEmpty) {
      setState(() => _error = 'Enter a passphrase.');
      return;
    }
    if (_passphraseController.text != _confirmController.text) {
      setState(() => _error = "Passphrases don't match.");
      return;
    }
    setState(() {
      _error = null;
      _saving = true;
    });
    try {
      final sealed = sealCurrentIdentity(
        recoveryWords: widget.summary.recoveryWords,
        nickname: widget.summary.nickname,
        passphrase: _passphraseController.text,
      );
      if (!kIsWeb) {
        final path = await _vaultPath();
        await File(path).writeAsBytes(sealed);
      }
      if (!mounted) return;
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(
          builder: (_) => SignedInScreen(summary: widget.summary, passphrase: _passphraseController.text),
        ),
        (route) => false,
      );
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Protect this device')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text(
                  'Set a passphrase to protect your identity on this device. Anyone with '
                  'access to this device would still need it to read your identity.',
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: _passphraseController,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'Passphrase', border: OutlineInputBorder()),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: _confirmController,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'Confirm passphrase', border: OutlineInputBorder()),
                ),
                const SizedBox(height: 16),
                if (_error != null) ...[
                  Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                  const SizedBox(height: 16),
                ],
                FilledButton(
                  onPressed: _saving ? null : _save,
                  child: _saving
                      ? const SizedBox(height: 16, width: 16, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Save and continue'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Shown at launch when a sealed identity already exists on this device.
class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key, required this.vaultPath});

  final String vaultPath;

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final _passphraseController = TextEditingController();
  String? _error;

  void _unlock() {
    setState(() => _error = null);
    try {
      final sealed = File(widget.vaultPath).readAsBytesSync();
      final summary = unlockIdentity(passphrase: _passphraseController.text, sealed: sealed);
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (_) => SignedInScreen(summary: summary, passphrase: _passphraseController.text),
        ),
      );
    } catch (e) {
      setState(() => _error = 'Could not unlock: wrong passphrase, or this file was tampered with.');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('lattice')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                TextField(
                  controller: _passphraseController,
                  obscureText: true,
                  autofocus: true,
                  onSubmitted: (_) => _unlock(),
                  decoration: const InputDecoration(labelText: 'Passphrase', border: OutlineInputBorder()),
                ),
                const SizedBox(height: 16),
                if (_error != null) ...[
                  Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                  const SizedBox(height: 16),
                ],
                FilledButton(onPressed: _unlock, child: const Text('Unlock')),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// The signed-in home state. Owns the one [InviteBookHandle] for the app session (see that
/// module's docs for why invites are session-lived, unlike identity/contacts) and the
/// passphrase used to seal the contacts vault, so the invite/contacts screens below don't
/// each need to ask for it again. Messaging and trust-tier UI are still unbuilt.
class SignedInScreen extends StatefulWidget {
  const SignedInScreen({super.key, required this.summary, required this.passphrase});

  final IdentitySummary summary;
  final String passphrase;

  @override
  State<SignedInScreen> createState() => _SignedInScreenState();
}

class _SignedInScreenState extends State<SignedInScreen> {
  final _inviteBook = InviteBookHandle();

  Future<void> _forgetDevice(BuildContext context) async {
    if (!kIsWeb) {
      for (final path in [await _vaultPath(), await _contactsVaultPath()]) {
        final file = File(path);
        if (file.existsSync()) await file.delete();
      }
    }
    if (!context.mounted) return;
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const HomeScreen()),
      (route) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('lattice')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text('Signed in as ${widget.summary.nickname}'),
                const SizedBox(height: 8),
                Text(widget.summary.localIdHex, style: const TextStyle(fontFamily: 'monospace')),
                const SizedBox(height: 32),
                FilledButton(
                  onPressed: () => Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => InviteScreen(inviteBook: _inviteBook, passphrase: widget.passphrase),
                    ),
                  ),
                  child: const Padding(
                    padding: EdgeInsets.symmetric(vertical: 12),
                    child: Text('Invite a contact'),
                  ),
                ),
                const SizedBox(height: 12),
                OutlinedButton(
                  onPressed: () => Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => ContactsScreen(passphrase: widget.passphrase)),
                  ),
                  child: const Padding(
                    padding: EdgeInsets.symmetric(vertical: 12),
                    child: Text('Contacts'),
                  ),
                ),
                const SizedBox(height: 32),
                const Text(
                  'Messaging and the trust-tier UI are still unbuilt. This screen proves '
                  'identity, local encrypted storage, invites, and contacts all work end to '
                  'end through lattice-core.',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 32),
                OutlinedButton(
                  onPressed: () => _forgetDevice(context),
                  child: const Text('Forget this device (testing)'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Issue invites and complete pending ones (see `invite.rs`'s module docs: only the issuer
/// acts here — completing means manually entering the invitee's fingerprint, since the real
/// network handshake isn't wired into this UI yet).
class InviteScreen extends StatefulWidget {
  const InviteScreen({super.key, required this.inviteBook, required this.passphrase});

  final InviteBookHandle inviteBook;
  final String passphrase;

  @override
  State<InviteScreen> createState() => _InviteScreenState();
}

class _PendingInvite {
  _PendingInvite(this.tokenText);
  final String tokenText;
  final _fingerprintController = TextEditingController();
  bool completed = false;
}

class _InviteScreenState extends State<InviteScreen> {
  final _pending = <_PendingInvite>[];
  String? _error;

  void _createInvite() {
    setState(() => _error = null);
    try {
      final token = widget.inviteBook.issue(ttlSecs: PlatformInt64Util.from(3600), now: _nowUnixSeconds());
      setState(() => _pending.add(_PendingInvite(token)));
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  Future<void> _complete(_PendingInvite invite) async {
    setState(() => _error = null);
    try {
      final path = await _contactsVaultPath();
      final file = File(path);
      final existing = !kIsWeb && file.existsSync() ? await file.readAsBytes() : null;

      final result = widget.inviteBook.complete(
        tokenText: invite.tokenText,
        contactFingerprintHex: invite._fingerprintController.text,
        existingSealedGraph: existing,
        passphrase: widget.passphrase,
        now: _nowUnixSeconds(),
      );

      if (!kIsWeb) await file.writeAsBytes(result.sealedGraph);
      setState(() => invite.completed = true);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Contact added.')));
    } catch (e) {
      setState(() => _error = 'Could not complete: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Invite a contact')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: ListView(
            padding: const EdgeInsets.all(24),
            children: [
              const Text(
                'Invites are personal and out-of-band: share the token below with someone you '
                'trust directly (in person, an existing secure chat, ...) — there is no '
                'discovery of strangers.',
              ),
              const SizedBox(height: 16),
              FilledButton(onPressed: _createInvite, child: const Text('Create invite (valid 1 hour)')),
              if (_error != null) ...[
                const SizedBox(height: 16),
                Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
              ],
              const SizedBox(height: 24),
              for (final invite in _pending) _PendingInviteCard(invite: invite, onComplete: () => _complete(invite)),
            ],
          ),
        ),
      ),
    );
  }
}

class _PendingInviteCard extends StatelessWidget {
  const _PendingInviteCard({required this.invite, required this.onComplete});

  final _PendingInvite invite;
  final VoidCallback onComplete;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 16),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text('Invite token (share this):'),
            const SizedBox(height: 4),
            SelectableText(invite.tokenText, style: const TextStyle(fontFamily: 'monospace')),
            const SizedBox(height: 12),
            if (invite.completed)
              const Text('Added as a contact.')
            else ...[
              TextField(
                controller: invite._fingerprintController,
                decoration: const InputDecoration(
                  labelText: "Invitee's fingerprint (from their signed-in screen)",
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 8),
              FilledButton(onPressed: onComplete, child: const Text('Complete invite')),
            ],
          ],
        ),
      ),
    );
  }
}

/// Lists contacts from the persisted, passphrase-sealed trust graph.
class ContactsScreen extends StatefulWidget {
  const ContactsScreen({super.key, required this.passphrase});

  final String passphrase;

  @override
  State<ContactsScreen> createState() => _ContactsScreenState();
}

class _ContactsScreenState extends State<ContactsScreen> {
  late Future<List<ContactSummary>> _contacts;

  @override
  void initState() {
    super.initState();
    _contacts = _load();
  }

  Future<List<ContactSummary>> _load() async {
    final path = await _contactsVaultPath();
    final file = File(path);
    final sealed = !kIsWeb && file.existsSync() ? await file.readAsBytes() : null;
    return listContacts(sealed: sealed, passphrase: widget.passphrase, now: _nowUnixSeconds());
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Contacts')),
      body: FutureBuilder<List<ContactSummary>>(
        future: _contacts,
        builder: (context, snapshot) {
          if (!snapshot.hasData) return const Center(child: CircularProgressIndicator());
          if (snapshot.hasError) return Center(child: Text('Could not load contacts: ${snapshot.error}'));
          final contacts = snapshot.data!;
          if (contacts.isEmpty) {
            return const Center(child: Text('No contacts yet — invite someone to get started.'));
          }
          return ListView.builder(
            itemCount: contacts.length,
            itemBuilder: (context, i) => ListTile(
              title: Text(contacts[i].fingerprintHex, style: const TextStyle(fontFamily: 'monospace')),
              subtitle: Text(contacts[i].tier),
            ),
          );
        },
      ),
    );
  }
}
