from django import forms

# Create new user form
class CreateUserForm(forms.Form):
    user_firstname = forms.CharField()
    user_lastname = forms.CharField()
    user_email = forms.EmailField()
    user_password = forms.CharField(min_length=8)


# Create new user form
class LoginUserForm(forms.Form):
    cust_name = forms.CharField()
    cust_password = forms.CharField()
    cust_qr_string = forms.CharField()
    cust_pin = forms.IntegerField(min_value=1000, max_value=9999)
