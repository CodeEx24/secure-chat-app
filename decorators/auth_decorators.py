from functools import wraps

from functools import wraps
from flask import redirect, url_for, session, render_template


def preventAuthenticated(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'is_logged_in' in session and session['is_logged_in'] == True:
            return redirect(url_for(f"home"))
        return fn(*args, **kwargs)
    return wrapper

def userRequired(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'is_logged_in' in session and session['is_logged_in'] == True:
            return fn(*args, **kwargs)
        else:
            return render_template('404.html'), 404
    return wrapper