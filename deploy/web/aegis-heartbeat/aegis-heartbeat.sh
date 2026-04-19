#!/usr/bin/env bash
# AMOSKYS Web — Aegis sensor heartbeat
# ──────────────────────────────────────────────────────────────────
# Exercises every Aegis sensor family so the Command Center shows
# a complete "all-systems firing" pattern in the live feed, not
# just the passive-observable families (http/db/rest).
#
# Expected to run on the lab EC2 via cron every 10 minutes:
#   */10 * * * * /usr/local/bin/aegis-heartbeat.sh >> /var/log/aegis-heartbeat.log 2>&1
#
# Runs as `ubuntu` (cron context). Uses `sudo -u www-data` for wp-cli
# commands so WordPress file-ownership stays correct.

set -eu
set -o pipefail

WP=/var/www/html
DOMAIN=https://lab.amoskys.com
TIMESTAMP=$(date -u +%FT%TZ)

echo "═══════════════════════════════════════════════════════════"
echo "aegis-heartbeat starting at $TIMESTAMP"

# Keep wp-cli output noise to a minimum
WP_CMD="sudo -u www-data wp --path=$WP --quiet"

# ──────────────────────────────────────────────────────────────
# 1. aegis.http.request + aegis.db.summary — every hit triggers these
# 2. aegis.rest.unauth_routes_detected — REST enumeration
# ──────────────────────────────────────────────────────────────
echo "[1-3] Pinging site for http/db/rest sensors..."
curl -sS -o /dev/null "$DOMAIN/" || true
curl -sS -o /dev/null "$DOMAIN/wp-json/" || true
curl -sS -o /dev/null "$DOMAIN/wp-json/wp/v2/posts" || true

# ──────────────────────────────────────────────────────────────
# 4. aegis.auth.login_failed — hit wp-login with wrong creds
# ──────────────────────────────────────────────────────────────
echo "[4] auth.login_failed..."
curl -sS -o /dev/null \
    -d "log=heartbeat-probe&pwd=notthepassword&wp-submit=Log+In" \
    "$DOMAIN/wp-login.php" || true

# ──────────────────────────────────────────────────────────────
# 5. aegis.plugin.activated + aegis.plugin.deactivated
# ──────────────────────────────────────────────────────────────
echo "[5] plugin.activated + plugin.deactivated..."
$WP_CMD plugin activate hello 2>/dev/null || true
$WP_CMD plugin deactivate hello 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
# 6. aegis.theme.switched — flip themes if we have a spare
# ──────────────────────────────────────────────────────────────
echo "[6] theme.switched..."
CURRENT_THEME=$($WP_CMD theme list --status=active --field=name 2>/dev/null || echo "")
SPARE_THEME=$($WP_CMD theme list --status=inactive --field=name 2>/dev/null | head -1 || echo "")
if [ -n "$SPARE_THEME" ] && [ -n "$CURRENT_THEME" ]; then
    $WP_CMD theme activate "$SPARE_THEME" 2>/dev/null || true
    sleep 1
    $WP_CMD theme activate "$CURRENT_THEME" 2>/dev/null || true
else
    echo "    (no spare theme available — skipping)"
fi

# ──────────────────────────────────────────────────────────────
# 7. aegis.fim.wpconfig_modified — mutate + trigger shutdown hook
# ──────────────────────────────────────────────────────────────
echo "[7] fim.wpconfig_modified..."
sudo sh -c "echo '// heartbeat $TIMESTAMP' >> $WP/wp-config.php"
# Trigger a request so the shutdown hook re-hashes + emits the event
curl -sS -o /dev/null "$DOMAIN/" || true

# ──────────────────────────────────────────────────────────────
# 8. aegis.outbound.http — WP update check hits api.wordpress.org
# ──────────────────────────────────────────────────────────────
echo "[8] outbound.http..."
$WP_CMD core check-update 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
# 9. aegis.options.updated + aegis.options.added
# ──────────────────────────────────────────────────────────────
echo "[9] options.updated + options.added..."
# heartbeat stamp option (add if missing, then update)
$WP_CMD option update amoskys_heartbeat_stamp "$TIMESTAMP" 2>/dev/null || true
# Also bump blogname briefly (updated event on existing option)
OLD_BLOGNAME=$($WP_CMD option get blogname 2>/dev/null || echo "AMOSKYS Lab")
$WP_CMD option update blogname "${OLD_BLOGNAME} (heartbeat)" 2>/dev/null || true
sleep 1
$WP_CMD option update blogname "$OLD_BLOGNAME" 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
# 10. aegis.cron.run — run any due cron jobs + emit the DOING_CRON event
# ──────────────────────────────────────────────────────────────
echo "[10] cron.run..."
$WP_CMD cron event run --due-now 2>/dev/null || true
# Also hit wp-cron.php directly to guarantee the DOING_CRON path
curl -sS -o /dev/null "$DOMAIN/wp-cron.php?doing_wp_cron" || true

# ──────────────────────────────────────────────────────────────
# 11. aegis.mail.failed — wp_mail without sendmail → warn-sev event
# ──────────────────────────────────────────────────────────────
echo "[11] mail.failed..."
$WP_CMD eval "wp_mail('heartbeat@amoskys.local', 'Heartbeat $TIMESTAMP', 'probe');" 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
# 12. aegis.post.saved + .status_change + .deleted
# ──────────────────────────────────────────────────────────────
echo "[12] post.* lifecycle..."
POST_ID=$($WP_CMD post create --post_title="Heartbeat $TIMESTAMP" \
    --post_content="probe" --post_status=draft --porcelain 2>/dev/null || echo "")
if [ -n "$POST_ID" ]; then
    $WP_CMD post update "$POST_ID" --post_status=publish 2>/dev/null || true
    $WP_CMD post delete "$POST_ID" --force 2>/dev/null || true
fi

# ──────────────────────────────────────────────────────────────
# 13. aegis.comment.posted — create a comment on post ID 1
# ──────────────────────────────────────────────────────────────
echo "[13] comment.posted..."
$WP_CMD comment create --comment_post_ID=1 \
    --comment_content="heartbeat $TIMESTAMP" \
    --comment_author="probe" \
    --comment_author_email="probe@amoskys.local" \
    --comment_approved=0 2>/dev/null || true
# Clean up old heartbeat comments (keep noise down)
$WP_CMD comment list --author=probe --field=comment_ID 2>/dev/null \
    | head -n -5 \
    | xargs -r -I {} $WP_CMD comment delete {} --force 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
# 14. aegis.media.uploaded + .deleted — tiny 1x1 PNG
# ──────────────────────────────────────────────────────────────
echo "[14] media.uploaded + .deleted..."
TMP_PNG=/tmp/aegis-heartbeat-$$.png
# Tiny valid 1x1 transparent PNG
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xcf\xc0\x00\x00\x00\x03\x00\x01\x5c\xcd\xff\x69\x00\x00\x00\x00IEND\xaeB`\x82' > $TMP_PNG
ATTACH_ID=$($WP_CMD media import "$TMP_PNG" --porcelain 2>/dev/null || echo "")
if [ -n "$ATTACH_ID" ]; then
    $WP_CMD post delete "$ATTACH_ID" --force 2>/dev/null || true
fi
rm -f $TMP_PNG

# ──────────────────────────────────────────────────────────────
# 15. aegis.admin.page_view — via logged-in REST with app password
# ──────────────────────────────────────────────────────────────
# Admin sensor needs an actual admin-area request. We use wp-cli eval
# to invoke admin_init manually (which fires the sensor's hook).
echo "[15] admin.page_view..."
$WP_CMD eval 'wp_set_current_user(1); set_current_screen("dashboard"); do_action("admin_init");' 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
# aegis.lifecycle.activated — intentionally NOT exercised here.
# It only fires on Aegis plugin activation. Re-activating Aegis
# in a cron would create chain-break anomalies.
# ──────────────────────────────────────────────────────────────

echo "heartbeat complete at $(date -u +%FT%TZ)"
echo "═══════════════════════════════════════════════════════════"
