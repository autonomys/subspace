import { EventRecord, Event } from "@polkadot/types/interfaces/system";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { SignedBlock } from "@polkadot/types/interfaces";

import { ParaHeadAndId, ParachainConfigType, ChainName } from "./types";
import Parachain from "./parachain";
import Target from "./target";
import logger from "./logger";

// TODO: consider moving to a separate utils module
// TODO: implement tests
export const getParaHeadAndIdFromEvent = (event: Event): ParaHeadAndId => {
    // use 'any' because this is not typed array - element can be number, string or Record<string, unknown>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { paraHead, paraId } = (event.toJSON().data as Array<any>)[0]
        .descriptor;

    return { paraHead, paraId };
};

// TODO: more explicit function name
export const isRelevantRecord =
    (index: number) =>
        ({ phase, event }: EventRecord): boolean => {
            return (
                // filter the specific events based on the phase and then the
                // index of our extrinsic in the block
                phase.isApplyExtrinsic &&
                phase.asApplyExtrinsic.eq(index) &&
                event.section == "paraInclusion" &&
                event.method == "CandidateIncluded"
            );
        };


type ParachainsMap = Map<ChainName, Parachain>;

export const createParachainsMap = async (
    target: Target,
    configParachains: ParachainConfigType[],
    signers: AddressOrPair[],
): Promise<ParachainsMap> => {
    const map = new Map();

    for (const [index, { url, chain, paraId }] of configParachains.entries()) {
        const signer = signers[index];
        const feedId = await target.getFeedId(signer);
        const parachain = new Parachain({ feedId, url, chain: chain as ChainName, logger, signer });
        map.set(paraId, parachain);
    }

    // TODO: investigate why this code results in Uknown paraId error
    // configParachains.forEach(async ({ url, chain, paraId }, index) => {
    //     const signer = signers[index];
    //     const feedId = await target.sendCreateFeedTx(signer);
    //     const parachain = new Parachain({ feedId, url, chain: chain as ChainName, logger, signer });
    //     map.set(paraId, parachain);
    // });

    return map;
};

export const isValidBlock = (block: SignedBlock): boolean => {
    return block && block.block && block.block.header && Boolean(block.block.extrinsics);
};
