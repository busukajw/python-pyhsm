#!/usr/bin/env python

import os
from app import create_app, db

if __name__ == '__main__':
    app = create_app(os.environ.get('FLASK_CONFIG', 'development'))
    with app.app_context():
        db.create_all()
    app.run()
