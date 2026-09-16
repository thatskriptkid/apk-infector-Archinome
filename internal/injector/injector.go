package injector

import (
	"path/filepath"
)

// Payload dex files injected as classesN.dex (or sealed into assets/) by the
// streaming repacker; see inject_zip.go for how each vector picks its stub.
var payload_custom_name, _ = filepath.Abs("payload_custom.dex")

// Куда writer кладёт переписанный stub dex перед упаковкой в APK.
var injectedAppPrevName, _ = filepath.Abs("InjectedApp_patched.dex")
var payload_frida_name, _ = filepath.Abs("payload_frida.dex")
var payload_provider_name, _ = filepath.Abs("payload_provider.dex")
var payload_trampoline_name, _ = filepath.Abs("payload_trampoline.dex")
var payload_receiver_name, _ = filepath.Abs("payload_receiver.dex")
var payload_appfactory_name, _ = filepath.Abs("payload_appfactory.dex")
var payload_assets_name, _ = filepath.Abs("payload_assets.dex")

// Stub dexes of the vectors 9..14: the code-patch vectors (9, 11) carry only the
// static entry point the patched host method calls, the manifest carriers
// (12, 13, 14) carry the component class the manifest names.
var payload_service_name, _ = filepath.Abs("payload_service.dex")
var payload_apppatch_name, _ = filepath.Abs("payload_apppatch.dex")
var payload_instrumentation_name, _ = filepath.Abs("payload_instrumentation.dex")
var payload_backupagent_name, _ = filepath.Abs("payload_backupagent.dex")
var payload_zygote_name, _ = filepath.Abs("payload_zygote.dex")

// The dex that gets sealed into assets/ instead of being injected as classesN.dex.
var payload_assets_dyn_name, _ = filepath.Abs("assets_payload/dyn_payload.dex")
