import os
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app(config_name):
    """
     Create application instance
    """

    app = Flask(__name__)
    #apply config
    cfg = os.path.join(os.getcwd(), 'config', config_name + '.py')
    app.config.from_pyfile(cfg)
    # init  database
    db.init_app(app)
    #register blueprints
    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint)

    return app