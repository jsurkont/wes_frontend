# Generated by Django 2.1.3 on 2018-11-15 13:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wes_frontend', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usertokens',
            name='user',
            field=models.CharField(max_length=256, unique=True),
        ),
    ]
