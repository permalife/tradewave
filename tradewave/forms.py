from django import forms
from tradewave.models import Article

# Create the form class.
class IssueCreditForm(forms.Form):
    recipient = forms.IntegerField()
    credit = forms.UUIDField()
    amount = forms.DecimalField(max_digits=12, decimal_places=2)
