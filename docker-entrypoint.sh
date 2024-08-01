flask db upgrade

<<<<<<< HEAD
exec guicorn --bind 0.0.0.0:80 "app:create_app()" 
=======
exec gunicorn --bind 0.0.0.0:80 "app:create_app()"
>>>>>>> 2bf4223cf17bbd173a73d8183a3ebdc9962fe81a
