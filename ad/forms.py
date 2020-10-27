from django import forms
from django.forms import ModelForm
from .models import Server
from django.contrib.auth.models import User

class AddServerForm(ModelForm):
    # shared_with = forms.ModelChoiceField(queryset=User.objects.all().order_by('-email'))
    class Meta:
        model = Server
        fields = ['name', 'save_reports', 'share_reports', 'shared_with', 'server_address', 'ssh_port']

    def save(self, commit=True, user_id=None):
        server = super(AddServerForm, self).save(commit=False)
        server.owner_id = user_id
        if commit:
            server.save()

class ServerCredentialsForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput())

class EmailForm(forms.Form):
    email = forms.EmailField()
