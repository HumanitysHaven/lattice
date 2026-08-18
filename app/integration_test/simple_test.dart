import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:app/main.dart';
import 'package:app/src/rust/frb_generated.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  testWidgets('creating an identity shows a 24-word recovery phrase and fingerprint', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const LatticeApp());
    await tester.pumpAndSettle();

    await tester.tap(find.text('Create a new identity'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'integration-test');
    await tester.tap(find.text('Generate identity'));
    await tester.pumpAndSettle();

    expect(find.textContaining('Fingerprint:'), findsOneWidget);
    expect(find.textContaining('Nickname: integration-test'), findsOneWidget);
    // 24 numbered recovery words, real output from lattice-core through the FFI bridge.
    expect(find.textContaining('24.'), findsOneWidget);
  });
}
