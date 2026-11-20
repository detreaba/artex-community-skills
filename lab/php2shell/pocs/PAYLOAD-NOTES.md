## payload-618 internal notes
CVE-2026-109618 - stale progress->post_bytes_processed, 149 packed reclaim, zend_call_function.

ARTEX payload library. Authoritative confirmation payload for this
check, staged by the owner session. TLS only when the URL scheme is https; behavior otherwise unchanged.

Outer zval* is cached once (session.c zend_hash_str_find of data["bytes_processed"]).
It is not refreshed on a later FILE_START. FILE_DATA writes it at
Z_LVAL_P(post_bytes_processed) = post_bytes, then php_session_rfc1867_update().
Second update after > session.upload_progress.min_freq (1s) decode+zend_hash_update
dtors the previous progress tree through HashTable.pDestructor = zval_ptr_dtor.
149 t[] parts are the packed natural table (nTableSize 256, 320-byte string bins).
File 2 FILE_DATA is the stale outer store. Same callback also stores
current_file_bytes_processed (inner). Profile ubuntu php 8.5.4:
zend_call_function = zval_ptr_dtor - 0x43EF0. Lab php 8.3.x official: delta 0xDBC0
(see php2shell/profile-deltas.tsv).

## payload-619 internal notes
CVE-2026-109619 - stale progress->current_file_bytes_processed, 149 packed reclaim, zend_call_function.

ARTEX payload library. Authoritative confirmation payload for this
check, staged by the owner session. TLS only when the URL scheme is https; --delta override.

Inner zval* is refreshed on every FILE_START (session.c:3342) and stored on FILE_DATA
at Z_LVAL_P(current_file_bytes_processed) = offset+length (session.c:3355), then
Z_LVAL_P(post_bytes_processed) = post_bytes (session.c:3356), then update().
One file, no second FILE_START, so the inner pointer stays cached across chunks.
Chunk after >1s min_freq: first post-stall FILE_DATA's update() dtors the decoded
progress tree (pDestructor = zval_ptr_dtor). The next FILE_DATA's two stores are
the stale writes. 149 t[] follow in the same body (packed natural table, 320-byte
string bins overlapping the freed arData). zend_call_function = zval_ptr_dtor - 0x43EF0
(Ubuntu 8.5.4 profile; lab php8.3 official delta 0xDBC0 — see profile-deltas.tsv).
