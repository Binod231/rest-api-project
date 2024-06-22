flask db upgrade

exec guicorn --bind 0.0.0.0:80 "app:create_app()"