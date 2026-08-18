import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:app/main.dart';
import 'package:app/src/rust/frb_generated.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  testWidgets(
    'create identity -> set passphrase -> persists -> forget device wipes it, end to end',
    (WidgetTester tester) async {
      await tester.pumpWidget(const LatticeApp());
      await tester.pumpAndSettle();

      // Fresh device: no stored identity, so we land on the create/restore choice.
      expect(find.text('Create a new identity'), findsOneWidget);

      await tester.tap(find.text('Create a new identity'));
      await tester.pumpAndSettle();

      await tester.enterText(find.byType(TextField), 'integration-test');
      await tester.tap(find.text('Generate identity'));
      await tester.pumpAndSettle();

      expect(find.textContaining('Fingerprint:'), findsOneWidget);
      expect(find.textContaining('Nickname: integration-test'), findsOneWidget);
      // 24 numbered recovery words, real output from lattice-core through the FFI bridge.
      expect(find.textContaining('24.'), findsOneWidget);

      await tester.tap(find.text("I've written it down"));
      await tester.pumpAndSettle();

      // Set a local storage passphrase; this calls sealCurrentIdentity and writes the vault.
      final passphraseFields = find.byType(TextField);
      await tester.enterText(passphraseFields.at(0), 'a test passphrase');
      await tester.enterText(passphraseFields.at(1), 'a test passphrase');
      await tester.tap(find.text('Save and continue'));
      await tester.pumpAndSettle();

      expect(find.textContaining('Signed in as integration-test'), findsOneWidget);

      // Relaunching the app now (without wiping storage) should skip straight to the
      // unlock screen, proving the vault actually persisted.
      await tester.pumpWidget(const LatticeApp());
      await tester.pumpAndSettle();
      expect(find.text('Unlock'), findsOneWidget);
      await tester.enterText(find.byType(TextField), 'a test passphrase');
      await tester.tap(find.text('Unlock'));
      await tester.pumpAndSettle();
      expect(find.textContaining('Signed in as integration-test'), findsOneWidget);

      // Clean up after the test: forgetting the device should wipe the vault and return to
      // the create/restore choice.
      await tester.tap(find.text('Forget this device (testing)'));
      await tester.pumpAndSettle();
      expect(find.text('Create a new identity'), findsOneWidget);
    },
  );
}
