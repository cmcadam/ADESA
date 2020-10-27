import io
from reportlab.lib.pagesizes import landscape
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.units import inch
from datetime import datetime, timezone
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponseBadRequest, FileResponse
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from django.contrib.auth.decorators import login_required

from .models import Server, Audit, Report
from .forms import AddServerForm, ServerCredentialsForm, EmailForm
from .validators import validIPAddress

from scripts.reporter import get_ad_info


@login_required
def auditor(request):
    servers = Server.objects.filter(owner_id=request.user.id)
    external_reports = Audit.objects.filter(user_id=request.user.id)
    context = {
        'servers': servers,
        'external_reports': external_reports,
    }
    return render(request, 'ad/auditor.html', context)


@login_required
def configuration(request):
    servers = Server.objects.filter(owner_id=request.user.id)
    context = {
        'servers': servers
        }
    return render(request, 'ad/configuration.html', context)


@login_required
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

    servers = Server.objects.filter(owner_id=request.user.id)
    # Find the newest version of the report
    for server in servers:
        if Report.objects.filter(server_id=server.id).order_by('-date_created').first() is not None:
            result = Report.objects.filter(server_id=server.id).order_by('-date_created').first()

    if result is not None:
        # Iterate through the report to get all the scores and details
        for category in result.json_report:
            for maturity_level in result.json_report[category]:
                for control in result.json_report[category][maturity_level]:
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

        # Determine the
        application_control_maturity = application_control_score / 7.0
        patching_application_maturity = patching_application_score / 7.0
        office_macros_maturity = office_macros_score / 8.0
        application_hardening_maturity = application_hardening_score / 9.0
        admin_privileges_maturity = admin_privileges_score / 7.0
        patching_os_maturity = patching_os_score / 7.0
        mfa_maturity = mfa_score / 9.0
        backup_maturity = backup_score / 13.0

        dict = {
            'application_control_maturity': application_control_maturity,
            'patching_application_maturity': patching_application_maturity,
            'office_macros_maturity': office_macros_maturity,
            'application_hardening_maturity': application_hardening_maturity,
            'admin_privileges_maturity': admin_privileges_maturity,
            'patching_os_maturity': patching_os_maturity,
            'mfa_maturity': mfa_maturity,
            'backup_maturity': backup_maturity
        }

        # Calculate the maturity score
        for i in dict:
            if 0 <= float(dict[i]) <= 1 / 3:
                dict[i] = 1
            elif 1 / 3 < dict[i] <= 2 / 3:
                dict[i] = 2
            elif 2 / 3 < dict[i] <= 1:
                dict[i] = 3

        ad_env_maturity = ad_env_score/67.0 * 3
        report_id = result.id

        context = {
            'result_dict': result,
            'application_control_score': {
                'score': application_control_score,
                'maturity_level': dict['application_control_maturity']
            },
            'patching_application_score': {
                'score': patching_application_score,
                'maturity_level': dict['patching_application_maturity']
            },
            'office_macros_score': {
                'score': office_macros_score,
                'maturity_level': dict['office_macros_maturity']
            },
            'application_hardening_score': {
                'score': application_hardening_score,
                'maturity_level': dict['application_hardening_maturity']
            },
            'admin_privileges_score': {
                'score': admin_privileges_score,
                'maturity_level': dict['admin_privileges_maturity']
            },
            'patching_os_score': {
                'score': patching_os_score,
                'maturity_level': dict['patching_os_maturity']
            },
            'mfa_score': {
                'score': mfa_score,
                'maturity_level': dict['mfa_maturity']
            },
            'backup_score': {
                'score': backup_score,
                'maturity_level': dict['backup_maturity']
            },

            'ad_env_score': ad_env_score,
            'days_since_last_audit': days_since_last_audit,
            'average_maturity_score': ad_env_maturity,
            'report_id': report_id
        }
        return render(request, 'ad/dashboard.html', context)
    else:
        return render(request, 'ad/dashboard.html')


@login_required
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


@login_required
def audit_details(request, pk):
    server = Server.objects.get(id=pk)

    context = {}
    return render(request, 'ad/audit_details.html', context)


@login_required
def authorize_audit(request, pk):
    if request.method == 'POST':
        form = ServerCredentialsForm(request.POST)
        if form.is_valid():
            server = Server.objects.get(id=pk)
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            try:
                result_dict = get_ad_info(server.server_address, username, password)

                report = Report.objects.create(
                    server_id=server.id,
                    json_report=result_dict,
                )
                if server.share_reports == 1:
                    auditor = User.objects.get(username=server.shared_with)
                    Audit.objects.create(
                        report_id=report.id,
                        user_id=auditor.id
                     )
                messages.success(request, 'Audit complete')
            except:
                messages.error(request, 'Unable to audit server')
                return HttpResponseBadRequest('This view can not handle method {0}'. \
                                       format(request.method), status=403)

    form = ServerCredentialsForm()
    context = {
        'form': form,
        'server_id': pk
    }
    return render(request, 'ad/server_credentials.html', context)


@login_required
def generate_report(request, pk, **kwargs):

    buffer = io.BytesIO()
    page_size = (15 * inch, 8 * inch)
    doc = SimpleDocTemplate(buffer, pagesize=landscape(page_size), leftMargin=-8*inch)
    elements = []
    data = []

    report = Report.objects.get(id=pk)
    tmp = []

    # TODO Add summary to first page

    for category in report.json_report:
        tmp.append(category)
        data.append(tmp)
        tmp = []
        for maturity_level in report.json_report[category]:
            tmp.append(maturity_level)
            data.append(tmp)
            tmp = []
            for control in report.json_report[category][maturity_level]:
                tmp.append(control)
                data.append(tmp)
                tmp = []
                for detail in report.json_report[category][maturity_level][control]:
                    if detail == 'Policy Score' and report.json_report[category][maturity_level][control][detail] == 1:
                        tmp.append(str(detail) + ':')
                        tmp.append('Passed!')
                        data.append(tmp)
                        tmp = []
                    elif detail == 'Policy Score' and report.json_report[category][maturity_level][control][detail] == 0:
                        tmp.append(str(detail) + ':')
                        tmp.append('Failed!')
                        data.append(tmp)
                        tmp = []
                    else:
                        tmp.append(str(detail) + ':')
                        tmp.append(str(report.json_report[category][maturity_level][control][detail]))
                        data.append(tmp)
                        tmp = []

    t = Table(data, colWidths=100, rowHeights=30)
    elements.append(t)
    doc.build(elements)
    buffer.seek(0)
    # Check if being called from the email to function
    if 'email_to' in kwargs:
        mail = EmailMessage(
            'ADESA Server Report',
            'Find attached server report for your viewing',
            'chrismcadam21@gmail.com',
            [kwargs['email_to']]
        )
        mail.attach('ADESA Report.pdf', buffer.getvalue(), 'application/pdf')
        mail.send()

        messages.success(request, 'Successfully sent email!')
        return redirect('dashboard')
    return FileResponse(buffer, as_attachment=True, filename='report.pdf')


@login_required
def edit_server(request, pk):
    if request.method == 'POST':
        form = AddServerForm(request.POST)
        if form.is_valid():
            form.save(user_id=request.user.id)
            messages.success(request, 'Successfully updated server details')
            return redirect('configuration')
    server = Server.objects.get(id=pk)
    form = AddServerForm(instance=server)
    context = {
        'form': form
    }
    return render(request, 'ad/add_server.html', context)


@login_required
def remove_server(request, pk):
    if request.method == 'POST':
        Server.objects.get(id=pk).delete()
        messages.success(request, 'Successfully removed server!')
        return redirect('configuration')

    server = Server.objects.get(id=pk)
    context = {
        'server': server
    }
    return render(request, 'ad/remove_server.html', context)


@login_required
def send_results(request, pk):
    if request.method == 'POST':
        form = EmailForm(request.POST)
        if form.is_valid():
            email_to = form.cleaned_data['email']
            return generate_report(request, pk, email_to=email_to)
    form = EmailForm()
    context = {
        'form': form
    }
    return render(request, 'ad/send_results.html', context)
