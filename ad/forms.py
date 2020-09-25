from django import forms
from django.forms import ModelForm
from .models import Server

class AddServerForm(ModelForm):
    class Meta:
        model = Server
        fields = ['name', 'save_reports', 'share_reports', 'save_server_details', 'server_address', 'ssh_port']

    def save(self, commit=True, user_id=None):
        server = super(AddServerForm, self).save(commit=False)
        server.owner_id = user_id
        if commit:
            server.save()

class ServerCredentialsForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput())
