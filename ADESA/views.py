from django.shortcuts import redirect

def index(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    else:
        return redirect('account_login')