from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Server, Audit
from .forms import AddServerForm, CustomForm


# TODO give option to delete the report afterwards
def auditor(request):
    context = {}
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
        if form.is_valid():
            messages.success(request, 'Successfully added a new server!')
            form.save(user_id=request.user.id)
            return redirect('configuration')
        else:
            messages.error(request, 'Unable to add server!')
            return redirect('add_server')

    form = AddServerForm()
    context = {'form': form}
    return render(request, 'ad/add_server.html', context)
