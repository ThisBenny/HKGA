# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['hkga.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['argon2._ffi', 'Crypto.Cipher._mode_gcm', 'Crypto.Hash.SHA256', 'Crypto.Random'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='hkga',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['lock.ico'],
)
