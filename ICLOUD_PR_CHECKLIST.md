# iCloud Drive PR Checklist

Manual checks worth running before opening the PR.

## Auth and session

- [ ] Create a fresh `iclouddrive` remote from scratch.
- [ ] Confirm Apple sign-in succeeds.
- [ ] Confirm trusted-device 2FA succeeds.
- [ ] If ADP is enabled, confirm first real access completes PCS consent/cookie staging.
- [ ] Run `./rclone -vv config reconnect icloud:` and confirm it completes.
- [ ] Run `./rclone -vv ls icloud:` after reconnect and confirm the saved session works.

## Basic listing

- [x] `./rclone ls icloud:`
- [x] `./rclone lsd icloud:`
- [x] `./rclone --max-depth=1 ls icloud:`

## Directory operations

- [x] `./rclone mkdir icloud:rclone-test`
- [x] `./rclone lsd icloud:`
- [x] `./rclone rmdir icloud:rclone-test`
- [x] Nested directory create/remove:

```bash
./rclone mkdir icloud:rclone-test/a/b/c
./rclone lsd icloud:rclone-test/a/b
./rclone purge icloud:rclone-test
```

## File operations

- [x] Upload a small file.
- [x] Download it back.
- [x] Read it with `cat`.
- [x] Delete it.
- [x] Move/rename it.
- [x] Overwrite an existing file.

```bash
printf 'hello\n' > /tmp/rclone-hello.txt
./rclone copyto /tmp/rclone-hello.txt icloud:rclone-test/hello.txt
./rclone cat icloud:rclone-test/hello.txt
./rclone copyto icloud:rclone-test/hello.txt /tmp/rclone-hello-back.txt
./rclone moveto icloud:rclone-test/hello.txt icloud:rclone-test/renamed.txt
./rclone delete icloud:rclone-test/renamed.txt
```

## Sync behavior

- [x] `sync --dry-run`
- [x] Real `sync`
- [x] Confirm deletes propagate as expected on a disposable tree

```bash
mkdir -p /tmp/rclone-sync-test/sub
printf 'a\n' > /tmp/rclone-sync-test/a.txt
printf 'b\n' > /tmp/rclone-sync-test/sub/b.txt
./rclone sync /tmp/rclone-sync-test icloud:rclone-test/sync --dry-run
./rclone sync /tmp/rclone-sync-test icloud:rclone-test/sync
./rclone ls icloud:rclone-test/sync
```

## Filename coverage

- [ ] Spaces in names
- [ ] Unicode names
- [ ] Nested paths

```bash
printf 'x\n' > "/tmp/file with spaces.txt"
printf 'y\n' > "/tmp/unicode-ngalan-ß.txt"
./rclone copyto "/tmp/file with spaces.txt" "icloud:rclone-test/file with spaces.txt"
./rclone copyto "/tmp/unicode-ngalan-ß.txt" "icloud:rclone-test/unicode-ngalan-ß.txt"
./rclone ls icloud:rclone-test
```

## Cleanup

- [ ] `./rclone purge icloud:rclone-test`
- [ ] Confirm the disposable test tree is gone

## Minimum confidence bar

Before opening the PR, at least verify:

- [ ] fresh config
- [ ] reconnect
- [ ] ls/lsd
- [ ] mkdir/rmdir
- [ ] upload/download
- [ ] move/delete
- [ ] one sync round-trip
- [ ] one ADP-enabled access path
