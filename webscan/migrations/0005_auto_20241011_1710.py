# Generated by Django 3.1.4 on 2024-10-11 09:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webscan', '0004_log'),
    ]

    operations = [
        migrations.AlterField(
            model_name='log',
            name='content_type',
            field=models.CharField(blank=True, max_length=100, null=True, verbose_name='内容类型'),
        ),
        migrations.AlterField(
            model_name='log',
            name='object_id',
            field=models.PositiveIntegerField(blank=True, null=True, verbose_name='对象ID'),
        ),
        migrations.AlterField(
            model_name='log',
            name='object_repr',
            field=models.CharField(blank=True, max_length=200, null=True, verbose_name='对象描述'),
        ),
    ]
