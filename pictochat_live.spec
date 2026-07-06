# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ["pictochat_live.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("icon.png", "."),
        ("macos_wifi_channel.m", "."),
    ],
    hiddenimports=[],
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
    [],
    exclude_binaries=True,
    name="PictoChat Interceptor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch="arm64",
    codesign_identity=None,
    entitlements_file=None,
    icon=["icon.png"],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="PictoChat Interceptor",
)
app = BUNDLE(
    coll,
    name="PictoChat Interceptor.app",
    icon="icon.png",
    bundle_identifier="uk.co.peterwarrington.pictochat-interceptor",
    info_plist={
        "CFBundleDisplayName": "PictoChat Interceptor",
        "NSHighResolutionCapable": True,
    },
)
