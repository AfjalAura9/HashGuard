from .forms import UserForm, ProfileForm

def profile_forms(request):
    if request.user.is_authenticated:
        user_form = UserForm(instance=request.user)
        profile_form = ProfileForm(instance=getattr(request.user, 'profile', None))
        return {'user_form': user_form, 'profile_form': profile_form}
    return {}