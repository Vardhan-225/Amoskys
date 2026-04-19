#!/usr/bin/env python3
"""Wire Aegis sensor strike handoffs → Block engine via WP action hook."""

SENSORS = "/var/www/html/wp-content/plugins/amoskys-aegis/includes/class-aegis-sensors.php"
BLOCK = "/var/www/html/wp-content/plugins/amoskys-aegis/includes/class-aegis-block.php"

# 1. Block engine listens to the strike action
with open(BLOCK) as f:
    bsrc = f.read()
if "amoskys_aegis_strike" not in bsrc:
    old = "add_action( 'plugins_loaded', array( $this, 'enforce' ), -1 );"
    new = old + "\n\t\tadd_action( 'amoskys_aegis_strike', array( $this, 'count_strike' ), 10, 2 );"
    bsrc = bsrc.replace(old, new)
    with open(BLOCK, "w") as f:
        f.write(bsrc)
    print("  ✓ Block engine listens on amoskys_aegis_strike")
else:
    print("  = Block already listens")

# 2. Sensors fire the strike action at burst-relevant points
with open(SENSORS) as f:
    ssrc = f.read()

# 2a. login_failed → auth_fail
if "'amoskys_aegis_strike', 'auth_fail'" not in ssrc:
    ssrc = ssrc.replace(
        "public function on_login_failed( string $user_login, $error ): void {",
        "public function on_login_failed( string $user_login, $error ): void {\n"
        "\t\t$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : null;\n"
        "\t\tif ( $ip ) { do_action( 'amoskys_aegis_strike', 'auth_fail', $ip ); }"
    )
    print("  ✓ login_failed → auth_fail strike")

# 2b. capability_denied → priv_esc
old_cap = "\t\t\tif ( in_array( $cap, $privileged, true ) && empty( $all_caps[ $cap ] ) ) {\n\t\t\t\t$this->emitter->emit(\n\t\t\t\t\t'aegis.capability.denied',"
new_cap = (
    "\t\t\tif ( in_array( $cap, $privileged, true ) && empty( $all_caps[ $cap ] ) ) {\n"
    "\t\t\t\t$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';\n"
    "\t\t\t\tif ( $ip ) { do_action( 'amoskys_aegis_strike', 'priv_esc', $ip ); }\n"
    "\t\t\t\t$this->emitter->emit(\n"
    "\t\t\t\t\t'aegis.capability.denied',"
)
if "'amoskys_aegis_strike', 'priv_esc'" not in ssrc and old_cap in ssrc:
    ssrc = ssrc.replace(old_cap, new_cap)
    print("  ✓ capability.denied → priv_esc strike")

# 2c. nonce_failed → nonce_fail
old_nonce = "\tpublic function on_nonce_user_logged_out( $user_id, $nonce_action ) {\n\t\t// WordPress passes through this filter when a nonce fails for a logged-out user.\n\t\t// We also catch the post-action variant via wp_verify_nonce returning false.\n\t\t$this->emitter->emit(\n\t\t\t'aegis.nonce.failed',"
new_nonce = (
    "\tpublic function on_nonce_user_logged_out( $user_id, $nonce_action ) {\n"
    "\t\t$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';\n"
    "\t\tif ( $ip ) { do_action( 'amoskys_aegis_strike', 'nonce_fail', $ip ); }\n"
    "\t\t$this->emitter->emit(\n"
    "\t\t\t'aegis.nonce.failed',"
)
if "'amoskys_aegis_strike', 'nonce_fail'" not in ssrc and old_nonce in ssrc:
    ssrc = ssrc.replace(old_nonce, new_nonce)
    print("  ✓ nonce.failed → nonce_fail strike")

# 2d. 404 suspicious → scanner_404
old_404 = "\t\t$this->emitter->emit(\n\t\t\t'aegis.404.observed',"
new_404 = (
    "\t\tif ( $this->is_suspicious_404_pattern() ) {\n"
    "\t\t\t$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';\n"
    "\t\t\tif ( $ip ) { do_action( 'amoskys_aegis_strike', 'scanner_404', $ip ); }\n"
    "\t\t}\n"
    "\t\t$this->emitter->emit(\n"
    "\t\t\t'aegis.404.observed',"
)
if "'amoskys_aegis_strike', 'scanner_404'" not in ssrc and old_404 in ssrc:
    ssrc = ssrc.replace(old_404, new_404)
    print("  ✓ 404.suspicious → scanner_404 strike")

# 2e. POI canary → poi_attempt (immediate block)
old_poi = "\t\t\t$this->emitter->emit(\n\t\t\t\t'aegis.rest.poi_canary',"
new_poi = (
    "\t\t\t$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';\n"
    "\t\t\tif ( $ip ) { do_action( 'amoskys_aegis_strike', 'poi_attempt', $ip ); }\n"
    "\t\t\t$this->emitter->emit(\n"
    "\t\t\t\t'aegis.rest.poi_canary',"
)
if "'amoskys_aegis_strike', 'poi_attempt'" not in ssrc and old_poi in ssrc:
    ssrc = ssrc.replace(old_poi, new_poi)
    print("  ✓ poi_canary → poi_attempt strike")

with open(SENSORS, "w") as f:
    f.write(ssrc)
print("all strike wiring complete")
