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

// The dex that gets sealed into assets/ instead of being injected as classesN.dex.
var payload_assets_dyn_name, _ = filepath.Abs("assets_payload/dyn_payload.dex")
