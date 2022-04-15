use cirrus_node::{
	cli::{Cli, RelayChainCli, Subcommand},
	service::{self, new_partial, start_parachain_node, CirrusRuntimeExecutor},
};
use cirrus_runtime::{Block, RuntimeApi};
use log::info;
use sc_cli::{Result, SubstrateCli};

macro_rules! construct_async_run {
	(|$components:ident, $cli:ident, $cmd:ident, $config:ident| $( $code:tt )* ) => {{
		let runner = $cli.create_runner($cmd)?;
		runner.async_run(|$config| {
			let $components = new_partial::<
				RuntimeApi,
				CirrusRuntimeExecutor,
				_
			>(
				&$config,
				service::parachain_build_import_queue,
			)?;
			let task_manager = $components.task_manager;
			{ $( $code )* }.map(|v| (v, task_manager))
		})
	}}
}

/// Parse command line arguments into service configuration.
pub fn main() -> Result<()> {
	let cli = Cli::from_args();

	match &cli.subcommand {
		Some(Subcommand::BuildSpec(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
		},
		Some(Subcommand::CheckBlock(cmd)) => {
			construct_async_run!(|components, cli, cmd, config| {
				Ok(cmd.run(components.client, components.import_queue))
			})
		},
		Some(Subcommand::ExportBlocks(cmd)) => {
			construct_async_run!(|components, cli, cmd, config| {
				Ok(cmd.run(components.client, config.database))
			})
		},
		Some(Subcommand::ExportState(cmd)) => {
			construct_async_run!(|components, cli, cmd, config| {
				Ok(cmd.run(components.client, config.chain_spec))
			})
		},
		Some(Subcommand::ImportBlocks(cmd)) => {
			construct_async_run!(|components, cli, cmd, config| {
				Ok(cmd.run(components.client, components.import_queue))
			})
		},
		Some(Subcommand::PurgeChain(cmd)) => {
			let runner = cli.create_runner(cmd)?;

			runner.sync_run(|config| {
				let polkadot_cli = RelayChainCli::new(
					&config,
					[RelayChainCli::executable_name()].iter().chain(cli.relaychain_args.iter()),
				);

				let polkadot_config = SubstrateCli::create_configuration(
					&polkadot_cli,
					&polkadot_cli,
					config.tokio_handle.clone(),
				)
				.map_err(|err| format!("Relay chain argument error: {}", err))?;

				cmd.run(config, polkadot_config)
			})
		},
		Some(Subcommand::Revert(cmd)) => {
			construct_async_run!(|components, cli, cmd, config| {
				Ok(cmd.run(components.client, components.backend))
			})
		},
		Some(Subcommand::Benchmark(cmd)) =>
			if cfg!(feature = "runtime-benchmarks") {
				let runner = cli.create_runner(cmd)?;

				runner.sync_run(|config| cmd.run::<Block, CirrusRuntimeExecutor>(config))
			} else {
				Err("Benchmarking wasn't enabled when building the node. \
				You can enable it with `--features runtime-benchmarks`."
					.into())
			},
		None => {
			let runner = cli.create_runner(&cli.run.normalize())?;

			runner.run_node_until_exit(|config| async move {
				let polkadot_cli = RelayChainCli::new(
					&config,
					[RelayChainCli::executable_name()].iter().chain(cli.relaychain_args.iter()),
				);

				let tokio_handle = config.tokio_handle.clone();
				let polkadot_config =
					SubstrateCli::create_configuration(&polkadot_cli, &polkadot_cli, tokio_handle)
						.map_err(|err| format!("Relay chain argument error: {}", err))?;

				info!("Is collating: {}", if config.role.is_authority() { "yes" } else { "no" });

				let primary_chain_full_node = {
					let span = sc_tracing::tracing::info_span!(
						sc_tracing::logging::PREFIX_LOG_SPAN,
						name = "Primarychain"
					);
					let _enter = span.enter();

					subspace_service::new_full::<
						subspace_runtime::RuntimeApi,
						subspace_node::ExecutorDispatch,
					>(polkadot_config, false)
					.map_err(|_| {
						sc_service::Error::Other("Failed to build a full subspace node".into())
					})?
				};

				start_parachain_node(config, primary_chain_full_node)
					.await
					.map(|r| r.0)
					.map_err(Into::into)
			})
		},
	}
}
