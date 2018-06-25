#!/usr/bin/env python
from flask_wtf import Form
from wtforms import StringField, IntegerField, BooleanField, DateField,DateTimeField
from wtforms.validators import DataRequired

class SearchForm(Form):
    server = StringField('server', validators = [DataRequired()])
    dt = DateField('Pick a date', format = '%d/%m/%Y')


