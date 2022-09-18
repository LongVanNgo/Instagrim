from flask import (Blueprint, g, redirect, render_template, session,
                   request, current_app, flash, url_for, send_from_directory)
from werkzeug.utils import secure_filename

import os
import hashlib

from instagrim.db import get_db

bp = Blueprint('instagrim', __name__, url_prefix='')

@bp.route('/')
def show_entries():
    db = get_db()
    c = db.execute("SELECT * FROM posts JOIN users ON posts.user_id=users.id;")
    entries = c.fetchall()
    return(render_template('show_entries.html', entries=entries))

@bp.route('/show/<int:id>',methods=['POST', 'GET'])
def show_entry(id):
#, methods=['POST', 'GET']

    # TODO Get a single post from the database

    if request.method == 'POST':
        db = get_db()
        db.execute("INSERT INTO messages (user_id, post_id, created, msg) VALUES (?,{},datetime('now'),?)".format(id),
                       (session['user_id'], request.form['message']))
        db.commit()
        flash('Comment posted', 'info')

        return(redirect(url_for('instagrim.show_entry',id=id)))

    db = get_db()
    c = db.execute("SELECT * FROM posts JOIN users ON posts.id={} WHERE posts.user_id=users.id;".format(id))
    #entry = []
    entry = c.fetchone()

    db = get_db()
    c = db.execute("SELECT * FROM messages JOIN users ON messages.post_id={} WHERE messages.user_id=users.id;".format(id))
    #entry = []
    comments = c.fetchall()
    return(render_template('show_entry.html', entry=entry, comments=comments))
    ###################################################################

    

    #if not session.get('logged_in'):
    #    # If the user is not logged in do not display the page
    #    # but redirect to the login page with an error
    #    flash("Login required.", "error")
    #    return(redirect(url_for('instagrim.login')))

    #if request.method == 'POST':
    #    db = get_db()
    #    db.execute("INSERT INTO messages (user_id, post_id, created, msg) VALUES (?,{},datetime('now'),?)".format(id),
    #                   (session['user_id'], request.form['message']))
    #    db.commit()
    #    flash('Comment posted', 'info')
    #        # Redirect to show the show_entry
    #    #return(redirect(url_for('instagrim.show_entry', entry=entry, entrymsg=entrymsg)))
    #        
#
    ## If no data was posted show the form
    #return(render_template('show_entry.html'))

@bp.route('/images/<path:filename>')
def image_file(filename):
    """ Serve user uploaded images during development. """
    return send_from_directory(current_app.config['STORAGE_DIR'], filename)
    

@bp.route('/add', methods=['POST', 'GET'])
def add_entry():

    if not session.get('logged_in'):
        # If the user is not logged in do not display the page
        # but redirect to the login page with an error
        flash("Login required.", "error")
        return(redirect(url_for('instagrim.login')))

    if request.method == 'POST':

        if 'file' not in request.files:
            # If no file was posted redirect back with error
            flash("No file selected for upload.", "error")
            return redirect(url_for('instagrim.add_entry'))

        file=request.files['file']
        if file.filename == '':
            # If filename is empty redirect back with an error
            flash("Invalid image file.", "error")
            return redirect(url_for('instagrim.add_entry'))
        
        else:
            # Everthing is fine, make the post 

            # Save the uploaded to harddisk
            filename = secure_filename(file.filename)
            file.save(os.path.join(current_app.config['STORAGE_DIR'], filename))

            db = get_db()
            db.execute("INSERT INTO posts (user_id, created, message, image) VALUES (?,datetime('now'),?,?)",
                       (session['user_id'], request.form['message'], filename))
            db.commit()
    
            flash('New post saved', 'info')
            # Redirect to show the new post
            return(redirect(url_for('instagrim.show_entries')))

    # If no data was posted show the form
    return(render_template('add_entry.html'))


@bp.route('/logout')
def logout():
    """Logs user out"""
    session.pop('logged_in', None)
    flash('You were logged out.','info')
    return redirect(url_for('instagrim.show_entries'))


@bp.route('/register', methods=['POST', 'GET'])
def register():
    """Registers a new user"""
    # If we receive form data register new user
    if request.method == 'POST':

        # TODO Check if username is available########################
        db = get_db()
        c = db.execute("SELECT username FROM users WHERE username=?", 
                       (request.form['username'],))
        username = c.fetchone()
        if username is not None:
            flash("Username '{}' already taken".format(request.form['username']), 'error')
            return render_template('register.html')
        #################################################################

        # TODO Check if the two passwords match ##########################
        password1 = request.form['password1']
        print("Pass1:",password1)
        password2 = request.form['password2']
        print("Pass2:",password2)
        
        if password1 != password2:
            flash("Passwords do not match, try again.", 'error')
            return render_template('register.html')
        ################################################################
        # TODO Maybe check if the password is a good one? ###############
        print(len(password1))
        print(len(password2))

        if len(password1) < 6 or len(password2) < 6:
            flash("Password is too weak, try again.", 'error')
            return render_template('register.html')
        #################################################################

        # If all is well create the user
        # TODO See previous TODOs
        hashed_password = hashlib.sha256(request.form['password1'].encode()).hexdigest()
        db=get_db()
        db.execute("INSERT INTO users (username, password) VALUES (?,?)",
                   (request.form['username'], hashed_password))
        db.commit()
        flash("User '{}' registered, you can now log in.".format(request.form['username']), 'info')
        
        return redirect(url_for('instagrim.login'))


    # If we receive no data just show the registration form
    else:
        return render_template('register.html')




@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in"""

    # If we receive form data try to log the user in
    if request.method == 'POST':

        # Connect to the database
        db = get_db()

        # Retrieve the users password from database (and check if user exist)
        c = db.execute("SELECT * FROM users WHERE username=?", 
                       (request.form['username'],))
        user = c.fetchone()
        # Check if a user was found
        if user is None:
            flash('User not found.', 'error')
            return render_template('login.html')

        # TODO: Check if the passwords match #############################################
        print("db password:",user['password'])
        hashed_password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        db = get_db()
        c = db.execute("SELECT * FROM users WHERE password=?", 
                       (str(hashed_password),))
        password = c.fetchone()
        
        if  password != user:
            flash('Invalid password.', 'error')
            return render_template('login.html')
        ######################################################################################

        # If everything is okay, log in the user 
        # TODO: See the previoius TODOs
        session['logged_in'] = True
        session['username'] = user['username']
        session['user_id'] = user['id']
        flash('You were logged in.', 'info')

        return redirect(url_for('instagrim.show_entries'))

    return render_template('login.html')



