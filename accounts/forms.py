from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User

class RegistrationForm(UserCreationForm):
    email = forms.EmailField()
    class Meta:
        model = User
        fields = ['full_name', 'email', 'gender', 'height', 'weight']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user
        
class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['full_name', 'gender', 'height', 'weight']