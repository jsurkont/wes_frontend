# Generated by Django 2.1.3 on 2018-11-15 13:17

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='UserTokens',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.CharField(max_length=256)),
                ('access_token', models.TextField()),
                ('refresh_token', models.TextField()),
            ],
        ),
    ]
