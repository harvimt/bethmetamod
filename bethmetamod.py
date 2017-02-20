# stuff

def init_vanilla():
    """init vanilla folder"""
    # TODO hash check files
    for path in recurse_files(Config.game.root_dir):
        r_path = Config.game.root_dir / path
        v_path = Config.VANILLA_DIR / path
        print(r_path, v_path)
        if not v_path.exists() or not samefile(str(r_path), str(v_path)):
            if v_path.exists():
                v_path.unlink()
            v_path.parent.mkdir(exist_ok=True, parents=True)
            create_hardlink(str(r_path), str(v_path))