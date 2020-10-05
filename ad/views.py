import json
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponseBadRequest, HttpResponse

from .models import Server, Audit, Report, TestClass
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
    context = {
        'servers': servers
        }
    return render(request, 'ad/configuration.html', context)


def dashboard(request):
    result = None
    servers = Server.objects.filter(owner_id=request.user.id)
    # Find the newest version of the report
    for server in servers:
        result = Report.objects.filter(server_id=server.id).order_by('-date_created').first()

    if result is not None:
        # Iterate through the report to get all the scores and details
        for category in result.json_report:
            for maturity_level in result.json_report[category]:
                for control in result.json_report[category][maturity_level]:
                    for details in result.json_report[category][maturity_level][control]:
                        print(details, result.json_report[category][maturity_level][control][details])

    context = {
        'result_dict': result
    }
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

            try:
                messages.success(request, 'Audit complete')
                result_dict = get_ad_info(server.server_address, username, password)
                TestClass.objects.create(test=result_dict)
                Report.objects.create(
                    server_id=server.id,
                    json_report=result_dict,
                )
            except:
                messages.error(request, 'Unable to audit server')
                return HttpResponseBadRequest('This view can not handle method {0}'. \
                                       format(request.method), status=403)

    form = ServerCredentialsForm()
    context = {
        'form': form,
        'server_id': id
    }
    return render(request, 'ad/server_credentials.html', context)
