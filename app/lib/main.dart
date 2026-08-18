import 'package:flutter/material.dart';
import 'package:app/src/rust/api/identity.dart';
import 'package:app/src/rust/frb_generated.dart';

Future<void> main() async {
  await RustLib.init();
  runApp(const LatticeApp());
}

class LatticeApp extends StatelessWidget {
  const LatticeApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'lattice',
      theme: ThemeData(colorSchemeSeed: Colors.deepPurple, useMaterial3: true),
      home: const HomeScreen(),
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

/// Shows the newly-generated (or restored) identity's recovery phrase and fingerprint.
/// Real, sensitive secret material from `lattice-core` — treated as such: no clipboard
/// helper, no "share" button, just what's needed to write it down.
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
          onPressed: () => Navigator.of(context).popUntil((route) => route.isFirst),
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
                        onPressed: () => Navigator.of(context).popUntil((route) => route.isFirst),
                        child: const Text('Done'),
                      ),
                    ],
                  ),
          ),
        ),
      ),
    );
  }
}
