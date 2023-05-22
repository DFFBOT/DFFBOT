import click

from dffbot.distance_generation import generate_distances, generate_distances_from_debug
from dffbot.distance_converter import convert_aflgo_to_dffbot, convert_dffbot_to_aflgo


@click.group(help="A small tool to generate distance files for directed-guiding fuzzing (AFLGo)")
def cli():
    pass


cli.add_command(generate_distances)
cli.add_command(generate_distances_from_debug)
cli.add_command(convert_aflgo_to_dffbot)
cli.add_command(convert_dffbot_to_aflgo)