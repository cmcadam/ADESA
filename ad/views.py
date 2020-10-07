import json
import reportlab
from datetime import datetime, timezone
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponseBadRequest, HttpResponse

from .models import Server, Audit, Report, TestClass
from .forms import AddServerForm, ServerCredentialsForm
from .validators import validIPAddress

from scripts.reporter import get_ad_info


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

    application_control_score = 0
    patching_application_score = 0
    office_macros_score = 0
    application_hardening_score = 0
    admin_privileges_score = 0
    patching_os_score = 0
    mfa_score = 0
    backup_score = 0
    ad_env_score = 0
    days_since_last_audit = 0

    servers = Server.objects.filter(owner_id=request.user.id)
    # Find the newest version of the report
    for server in servers:
        result = Report.objects.filter(server_id=server.id).order_by('-date_created').first()

    if result is not None:
        # Iterate through the report to get all the scores and details
        for category in result.json_report:
            for maturity_level in result.json_report[category]:
                for control in result.json_report[category][maturity_level]:
                    # for details in result.json_report[category][maturity_level][control]:
                    if result.json_report[category][maturity_level][control]['Policy Score'] == 1:
                        if category == 'Application Control':
                            application_control_score += 1
                        if category == 'Patch Applications':
                            patching_application_score += 1
                        if category == 'Microsoft Office Macros':
                            office_macros_score += 1
                        if category == 'User Application Hardening':
                            application_hardening_score += 1
                        if category == 'Restrict Administrative Privileges':
                            admin_privileges_score += 1
                        if category == 'Patch Operating Systems':
                            patching_os_score += 1
                        if category == 'Multi-factor Authentication':
                            mfa_score += 1
                        if category == 'Daily Backups':
                            backup_score += 1

        ad_env_score = application_control_score + patching_application_score + office_macros_score + application_hardening_score + admin_privileges_score + patching_os_score + mfa_score + backup_score
        days_since_last_audit = (datetime.now(timezone.utc) - result.date_created).days

    context = {
        'result_dict': result,
        'application_control_score': application_control_score,
        'patching_application_score': patching_application_score,
        'office_macros_score': office_macros_score,
        'application_hardening_score': application_hardening_score,
        'admin_privileges_score': admin_privileges_score,
        'patching_os_score': patching_os_score,
        'mfa_score': mfa_score,
        'backup_score': backup_score,
        'ad_env_score': ad_env_score,
        'days_since_last_audit': days_since_last_audit
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


def authorize_audit(request, id):
    if request.method == 'POST':
        form = ServerCredentialsForm(request.POST)
        if form.is_valid():
            server = Server.objects.get(id=id)
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            try:
                result_dict = get_ad_info(server.server_address, username, password)
                # TestClass.objects.create(test=result_dict)
                Report.objects.create(
                    server_id=server.id,
                    json_report=result_dict,
                )
                messages.success(request, 'Audit complete')
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
