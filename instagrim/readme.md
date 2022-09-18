# Windows cmd:
set FLASK_APP=instagrim
cd instagrim2 
flask init-db
flask run

# Linux/Mac terminal
export FLASK_APP=instagrim
cd instagrim2
flask init-db
flask run

# Debug mode
Set the following environment variable as well
Windows: set FLASK_ENV=development
Linux/Mac: export FLASK_ENV=development

# Change database schema (alter/add tables)
Edit your-project-folder/instagrim/schema.sql.
Delete your-project-folder/instance/instagrim.db.
Rerun 'flask init-db'.
