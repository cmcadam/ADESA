from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponseBadRequest

from .models import Server, Audit
from .forms import AddServerForm, ServerCredentialsForm
from .validators import validIPAddress

from scripts.cmd import get_ad_info


def auditor(request):
    servers = Server.objects.filter(owner_id=request.user.id)
    external_reports = Audit.objects.filter(user_id=request.user.id)
    context = {
        'servers': servers,
        'external_reports': external_reports,
    }
    return render(request, 'ad/auditor.html', context)


def configuration(request):
    servers = Server.objects.filter(owner_id=request.user.id)
    # custom_form = CustomForm()
    for server in servers:
        print(server.id)
        # shared_with = Audit.objects.filter(server)

    context = {
        # 'form': form,
        'servers': servers
        }
    return render(request, 'ad/configuration.html', context)


def dashboard(request):
    context = {}
    return render(request, 'ad/dashboard.html', context)


def add_server(request):
    if request.method == 'POST':
        form = AddServerForm(request.POST)
        if form.is_valid() and validIPAddress(form.cleaned_data['server_address']):
            messages.success(request, 'Successfully added a new server!')
            form.save(user_id=request.user.id)
            return redirect('configuration')
        else:
            messages.error(request, 'Unable to add server!')
            return redirect('add_server')

    form = AddServerForm()
    context = {'form': form}
    return render(request, 'ad/add_server.html', context)


def audit_details(request, id):
    server = Server.objects.get(id=id)

    context = {}
    return render(request, 'ad/audit_details.html', context)

# TODO post form data to new endpoint using ajax
def authorize_audit(request, id):
    if request.method == 'POST':
        form = ServerCredentialsForm(request.POST)
        if form.is_valid():
            server = Server.objects.get(id=id)
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            print(username, password)
            # try:
            messages.success(request, 'Audit complete')
            get_ad_info(server.server_address, username, password)
            return redirect('authorize_audit', id=id)
            # except:
            #     messages.error(request, 'Unable to audit server')
            #     return HttpResponseBadRequest('This view can not handle method {0}'. \
            #                            format(request.method), status=403)
                # messages.error(request, 'Unable to audit server')
                # return redirect('authorize_audit', id=id)

    form = ServerCredentialsForm()
    context = {
        'form': form,
        'server_id': id
    }
    return render(request, 'ad/server_credentials.html', context)
