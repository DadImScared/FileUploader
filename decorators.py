
from threading import Thread
from flask import flash
from models import User
from flask import redirect, url_for, g, Markup
from functools import wraps


def async(f):
    def wrapper(*args, **kwargs):
        thr = Thread(target=f, args=args, kwargs=kwargs)
        thr.start()
    return wrapper


def authenticated(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not g.user.email_confirmed:
            flash(
                Markup('Your email is not confirmed click <a href="{}" class="alert-link">here</a> to confirm'.format(
                    url_for('send_confirm_email')
                )), "danger")
            return redirect(url_for('index'))
        if not g.user.admin_confirmed:
            flash("Admin has not confirmed you. Please click here to contact an admin", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper


def role_required(roles):
    def real_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            required = []
            user_role = g.user.get_role().role.name
            for role in roles:
                required.append(role)
            if not user_role:
                return redirect(url_for('index'))
            if user_role not in required:
                return redirect(url_for('index'))
            # if g.user.has_role('superadmin'):
            #     return f(*args, **kwargs)
            # if not g.user.has_role(role):
            #     return redirect(url_for('index'))

            return f(*args, **kwargs)
        return wrapper
    return real_decorator