{#
    Override default dbt schema naming so staging/marts models go into the same
    BigQuery dataset as the sources. Keeps us out of dataset-level IAM gymnastics.
    Tables are still separated by name prefix (stg_*, mart_*).
#}
{% macro generate_schema_name(custom_schema_name, node) -%}
    {{ target.schema }}
{%- endmacro %}
