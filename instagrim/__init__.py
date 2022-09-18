import os, sys
from flask import Flask

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.path.join(app.instance_path, 'instagrim.db.sqlite3'),
        STORAGE_DIR=os.path.join(app.instance_path, 'images'),
        SECRET_KEY="dev" # Override with instance config (this is insecure)
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
        os.makedirs(app.config['STORAGE_DIR'])
        print("Instance folder: ", app.instance_path)
    except OSError as e:
        # How to properly handle this?
        # On first ever request to the app folders are created,
        # on subsequent requests the folders already exist.
        pass
        
    from . import db
    db.init_app(app)

    from . import instagrim 
    app.register_blueprint(instagrim.bp)

    return app
