from django.contrib import admin


class BaseAdmin(admin.ModelAdmin):

    default_readonly_fields = ('uuid',)
    list_display = ('uuid',)
    search_fields = ('uuid',)
    readonly_fields = tuple()

    def __init__(self, model, admin_site):
        super().__init__(model, admin_site)
        self.readonly_fields += self.default_readonly_fields
