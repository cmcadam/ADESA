from django.shortcuts import render

# TODO give option to delete the report afterwards
def auditor(request):
    context = {}
    return render(request, 'ad/auditor.html', context)

def configuration(request):
    context = {}
    return render(request, 'ad/configuration.html', context)

def dashboard(request):
    context = {}
    return render(request, 'ad/dashboard.html', context)