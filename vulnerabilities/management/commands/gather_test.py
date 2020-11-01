from datetime import datetime

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from vulnerabilities.models import Importer
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importer_yielder import load_importers


class Command(BaseCommand):
    help = 'Import vulnerability data'

    def add_arguments(self, parser):

        parser.add_argument('sources', nargs='*',
                            help='Data sources from which to import')

    def handle(self, *args, **options):
        # load_importers() seeds the DB with Importers
        load_importers()

        sources = options['sources']
        if not sources:
            raise CommandError(
                'Please provide at least one data source to import from or use "--all".')

        self.import_data(sources)


    def import_data(self, names, cutoff_date):
        importers = []
        unknown_importers = set()
        # make sure all arguments are valid before running any importers
        for name in names:
            try:
                importers.append(Importer.objects.get(name=name))
            except Importer.DoesNotExist:
                unknown_importers.add(name)

        if unknown_importers:
            unknown_importers = ', '.join(unknown_importers)
            raise CommandError(f'Unknown data sources: {unknown_importers}')

        self._import_data(importers, cutoff_date)

    def _import_data(self, importers, cutoff_date):
        for importer in importers:
            self.stdout.write(f'Importing data from {importer.name}')
            batch_size = int(getattr(self, 'batch_size', 10))
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully imported data from {importer.name}'))
