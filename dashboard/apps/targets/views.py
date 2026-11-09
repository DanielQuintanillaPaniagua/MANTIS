"""Views for targets."""

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from .forms import TargetForm
from .models import TargetRecord


def target_list(request):
    targets = TargetRecord.objects.all()
    return render(request, "targets/target_list.html", {"targets": targets})


def target_new(request):
    if request.method == "POST":
        form = TargetForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Target created.")
            return redirect("targets:list")
    else:
        form = TargetForm()
    return render(request, "targets/target_form.html", {"form": form, "title": "New Target"})


def target_edit(request, pk):
    target = get_object_or_404(TargetRecord, pk=pk)
    if request.method == "POST":
        form = TargetForm(request.POST, instance=target)
        if form.is_valid():
            form.save()
            messages.success(request, "Target updated.")
            return redirect("targets:list")
    else:
        form = TargetForm(instance=target)
    return render(request, "targets/target_form.html", {"form": form, "title": f"Edit {target.name}"})


def target_delete(request, pk):
    target = get_object_or_404(TargetRecord, pk=pk)
    if request.method == "POST":
        target.delete()
        messages.success(request, "Target deleted.")
        return redirect("targets:list")
    return render(request, "targets/target_confirm_delete.html", {"target": target})