import numpy as np
from streamad.base import BaseDetector
from collections import deque
from collections.abc import Iterable


# using RedefStructs
# using Wavelets
# using Statistics
# using OnlineStats
# import LinearAlgebra: norm

include("AdaptiveResonanceCompact.jl")

class ClassifyState:
    art = AdaptiveResonance.DVFA()
    last_anomaly_i :int = 0
    last_anomaly_sim :float = 0.0
    last_rho_update_i :int = 0
    mask_after_cat :bool = False
    no_new_cat_count :int = 0
    trend_window_f = []
    # ::Vector{float}
    anomaly_sim_history = []
    # ::Vector{float}
    sim_diff_window = []
    # ::Mean{float, EqualWeight}
    rho_ub_mean = OnlineStats.Mean()
    # ::Vector{float}
    sim_window = []
    # ::Vector{float}
    ds_window = []
    ds_moving_average :float = 0.0
    # ::Vector{Int}
    medbin = []
    medlevel :int = 0
    belowmed :int = 0
    abovemed :int = 0
    # ::Vector{float}
    f_window = []
    dsi :int = 1


class P:
    i :int = 1
    cs = ClassifyState()
    wavelett = wavelet(WT.haar)
    # ::String
    datafile = ""
    dmin :float = 0.0
    dmax :float = 0.0
    dlength :int = 0
    window :int = 8
    probationary_period :int = 0
    windows_per_pb = 13
    sstep :int = 1
    discretize_chomp :float = 0.075
    nlevels :int = 80
    mask_rho_after_anomaly :int = 0
    trend_window :int = 0
    initial_rho :float = 0.80


class ARTime(BaseDetector):

    def __init__(self, dmin, dmax, dlength, p=p):
        p.dmin = dmin
        p.dmax = dmax
        p.dlength = dlength
        probationary_period = dlength < 5000 ? Int.(floor(0.15 * dlength)) : 750
        p.probationary_period = probationary_period - mod(probationary_period, 2) # make an even number
        p.sstep = max(1, round(Int, div(p.probationary_period, p.window * p.windows_per_pb)))
        p.trend_window = floor(Int, p.probationary_period / p.sstep)
        p.mask_rho_after_anomaly = p.window * 1.5
        # initialise detector state variables
        p.cs.sim_window = ones(p.trend_window ÷ 2 + 1)
        p.cs.sim_diff_window = zeros(p.trend_window + 1)
        p.cs.ds_window = zeros(p.sstep) # downsampling window
        p.cs.medbin = zeros(Int, p.nlevels + 1)
        p.cs.f_window = zeros(p.window)


    def process_sample(di, p=p):
        i = p.i
        p.cs.ds_window = [p.cs.ds_window[2:end];di]
        anomaly = 0.0
        if mod(i,p.sstep) == 0:
            # Downsample
            mean = Statistics.mean(p.cs.ds_window)
            max = maximum(p.cs.ds_window)
            min = minimum(p.cs.ds_window)
            if p.cs.dsi == 1:
                p.cs.ds_moving_average = mean
            p.cs.ds_moving_average = (p.cs.ds_moving_average + mean) / 2
            ds = max
            # Spike below the mean
            if abs(max - p.cs.ds_moving_average) < abs(min - p.cs.ds_moving_average):
                ds = min
            if abs(ds - mean) < (0.1 * mean): # spike must be at least 10%
                ds = mean
            # Normalize
            ds = ds - p.dmin
            if (p.dmax - p.dmin) != 0:
                ds = ds / (p.dmax - p.dmin)
            # Discretize
            level = round(Int, ds * p.nlevels)
            ds = level / p.nlevels
            # Levelize
            p.cs.medbin[level + 1] += 1
            medpos = p.cs.dsi ÷ 2
            if p.cs.dsi == 1:
                p.cs.medlevel = level
            if p.cs.medlevel > level:
                p.cs.belowmed += 1
            elif p.cs.medlevel < level:
                p.cs.abovemed += 1
            # Not strictly a running median but close enough
            if medpos < p.cs.abovemed:
                p.cs.belowmed += p.cs.medbin[p.cs.medlevel + 1]
                p.cs.medlevel += 1
                while p.cs.medbin[p.cs.medlevel+1] == 0:
                    p.cs.medlevel += 1
                p.cs.abovemed -= p.cs.medbin[p.cs.medlevel + 1]
            elif medpos < p.cs.belowmed:
                p.cs.abovemed += p.cs.medbin[p.cs.medlevel + 1]
                p.cs.medlevel -= 1
                while p.cs.medbin[p.cs.medlevel + 1] == 0:
                    p.cs.medlevel -= 1
                p.cs.belowmed -= p.cs.medbin[p.cs.medlevel + 1]

            med = p.cs.medlevel / p.nlevels
            if Base.abs(ds - med) < p.discretize_chomp:
                ds = med
            # Extract features
            features = zeros(p.window * 2)
            p.cs.f_window = [p.cs.f_window[2:end];ds]
            if p.cs.dsi >= p.window:
                dw = copy(p.cs.f_window)
                dw_min = minimum(dw)
                dw = dw .- dw_min
                dw_max = maximum(dw)
                if dw_max != 0:
                    dw = dw ./ dw_max
                fw = dwt(dw, p.wavelett)
                fw_min = minimum(fw)
                fw = (fw .- fw_min)
                fw_max = maximum(fw)
                if fw_max != 0:
                    fw = fw ./ fw_max
                features = [fw;p.cs.f_window]

            anomaly = process_features!(features, p.cs.dsi, p)
            p.cs.dsi += 1

        p.i += 1
        return anomaly


    def process_features(f, i, p):
        anomaly = 0.0
        if i <= p.trend_window:
            # Here we could build a matrix instead of an array
            push(p.cs.trend_window_f, f)
            # Batch process the probationary period
            if i == p.trend_window:
                features_mat = hcat(p.cs.trend_window_f...)
                p.cs.art.config.dim = length(f)
                p.cs.art.config.dim_comp = 2 * p.cs.art.config.dim
                p.cs.art.config.setup = true
                rho = init_rho(features_mat[:,p.window:p.trend_window], p)
                update_rho(rho, rho, p.cs.art)
                for (fi, ff) in enumerate(eachcol(features_mat)):
                    detect(ff, fi, p)
        else:
            anomaly = detect(f, i, p)
        return anomaly

    def detect(f, i, p):
        update_rho_after_anomaly = (i - p.cs.last_anomaly_i) == p.mask_rho_after_anomaly
        update_rho_for_trend = (i - p.cs.last_rho_update_i) >= p.trend_window ÷ 2
        mask_after_anomaly = (i - p.cs.last_anomaly_i) <= p.mask_rho_after_anomaly
        if i > p.trend_window + p.mask_rho_after_anomaly && p.cs.mask_after_cat:
            if p.cs.no_new_cat_count >= p.mask_rho_after_anomaly:
                p.cs.mask_after_cat = False

        # The samples prior to a complete feature window are not used for training
        # Call train! anyway but don't learn - this keeps ART indexes and arrays aligned with input data
        if i < p.window:
            AdaptiveResonance.train(p.cs.art, f, learning=False)
            cat = -1
        else:
            cat = AdaptiveResonance.train(p.cs.art, f)

        p.cs.no_new_cat_count = cat == -1 ? 0 : p.cs.no_new_cat_count + 1
        OnlineStats.fit(p.cs.rho_ub_mean, p.cs.art.A[i]) # running mean
        p.cs.sim_window = [p.cs.sim_window[2:end];p.cs.art.A[i]]
        p.cs.sim_diff_window = [p.cs.sim_diff_window[2:end];p.cs.art.opts.rho_ub - p.cs.art.A[i]]
        # Store the smallest similarity during the masking window for each anomaly
        if (i - p.cs.last_anomaly_i) < p.mask_rho_after_anomaly && length(p.cs.anomaly_sim_history) > 0:
            if p.cs.art.A[i] < p.cs.anomaly_sim_history[end]:
                p.cs.anomaly_sim_history[end] = p.cs.art.A[i]

        masking_anomaly = p.cs.mask_after_cat || mask_after_anomaly
        below_last_scale = mask_after_anomaly ? 0.90 : 0.70
        below_last = p.cs.art.A[i] < p.cs.last_anomaly_sim * below_last_scale
        anomaly_with_cat = cat == -1 && (!masking_anomaly || below_last)
        if i > p.trend_window && anomaly_with_cat:
            anomaly = confidence(p.cs.art.A[i], p.cs.art.Ae[i], p)
            push(p.cs.anomaly_sim_history, p.cs.art.A[i])
            p.cs.last_anomaly_sim = p.cs.art.A[i]
            p.cs.last_anomaly_i = i
        else:
            anomaly = 0.0

        p.cs.mask_after_cat = cat == -1 || p.cs.mask_after_cat
        # ART could use supervised learning to improve here, but NAB does not allow this
        if i > p.trend_window && (update_rho_after_anomaly || update_rho_for_trend):
            min_sim_in_trend_window = minimum(p.cs.sim_window)
            new_rho_ub = OnlineStats.value(p.cs.rho_ub_mean)
            new_rho_ub = min(0.97, new_rho_ub) # capping ub
            prev_rho_lb = p.cs.art.opts.rho_lb
            if prev_rho_lb <= min_sim_in_trend_window:
                incr = (min_sim_in_trend_window - prev_rho_lb) * 0.19
                new_rho_lb = prev_rho_lb + incr
            else:
                decr = 0.0
                if i > p.trend_window * 2:
                    below_rho_idxs = findall(x -> x > 0.05, p.cs.sim_diff_window)
                    below_rho = p.cs.sim_diff_window[below_rho_idxs]
                    below_rho = map(x -> min(0.37, x), below_rho)
                    if length(below_rho) > 0:
                        decr = mean(below_rho)
                decr = max(0.01, decr)
                new_rho_lb = prev_rho_lb - (decr / 2)
                if length(p.cs.anomaly_sim_history) > 0:
                    new_rho_lb = max(mean(p.cs.anomaly_sim_history), new_rho_lb)

            new_rho_lb = min(new_rho_ub, new_rho_lb)
            update_rho(new_rho_lb, new_rho_ub, p.cs.art)
            p.cs.last_rho_update_i = i
            p.cs.mask_after_cat = True
        return anomaly


    def confidence(features_sim, energy_sim, p):
        features_sim = min(0.999, features_sim)
        ub = ((1 - features_sim) - (1-p.cs.art.opts.rho_ub))/(1-features_sim)
        lb = ((1 - features_sim) - (1-p.cs.art.opts.rho_lb))/(1-features_sim)
        s = (ub*0.35 + lb*0.65) + (1.0 - energy_sim)*1.5
        s = min(1.0, s)
        return round(s, digits=6)

    def init_rho(raw_x_optim, p):
        lengthx = len(raw_x_optim[1,:])
        raw_x_sort = raw_x_optim
        # Build a similarity matrix
        sim = ones(lengthx, lengthx)
        for i in range(1,lengthx):
            for j in range(1,lengthx):
                if j >= i:
                    continue # symmetrical so save some computation

                sim_score = similarity(raw_x_optim[:,i], raw_x_optim[:,j])
                sim[i,j] = sim_score
                sim[j,i] = sim_score

        sim_sum = zeros(lengthx)
        for i in range(1,lengthx):
            sim_sum[i] = sum(sim[:,i])

        sim_order = sortperm(sim_sum)
        raw_x_sort = copy(raw_x_optim)
        for (i1,i2) in enumerate(sim_order):
            raw_x_sort[:,i1] = raw_x_optim[:,i2]

        # Find initial rho
        art = AdaptiveResonance.DVFA()
        art.config = p.cs.art.config
        opt_rho = p.initial_rho
        update_rho(opt_rho, opt_rho, art)
        AdaptiveResonance.train(art, raw_x_sort)
        return mean(art.A[p.trend_window ÷ 2:end])

    # Close to cosine similarity
    def similarity(t1, t2):
        nt1 = norm(t1)
        nt2 = norm(t2)
        if nt1 == 0.0:
            s = 1 - nt2
        else:
            if nt2 == 0.0:
                s = 1 - nt1
            else:
                s = sum(t1 .* t2) / (nt1 * nt2)
        return s


    def update_rho(rho_lb, rho_ub, art):
        art.opts.rho_lb = float.(rho_lb)
        art.opts.rho_ub = float.(rho_ub)


=================================================================================================================
=================================================================================================================

below is AdaptiveResonanceCompact.jl

=================================================================================================================
=================================================================================================================



using Parameters    # ARTopts are parameters (@with_kw)
using Logging       # Logging utils used as main method of terminal reporting
using LinearAlgebra: norm   # Trace and norms
using Statistics: median, mean  # Medians and mean for linkage methods

# Abstract types
abstract type ARTOpts end               # ART module options
abstract type ARTModule end             # ART modules
abstract type ART <: ARTModule end      # ART (unsupervised)

class DataConfig:
    # ::Bool
    setup: bool = False
    # ::int
    dim: int = 0
    # ::int
    dim_comp: int = 0




class opts_DVFA (ARTOpts @deftype float):
    # Lower-bound vigilance parameter: [0, 1]
    rho_lb = 0.0
    assert rho_lb >= 0.0 and rho_lb <= 1.0
    # Upper bound vigilance parameter: [0, 1]
    rho_ub = 0.0
    assert rho_ub >= 0.0 and rho_ub <= 1.0
 # opts_DVFA

class DVFA (ART):
    # Get parameters
    opts :opts_DVFA
    config :DataConfig
    # Working variables
    labels :Vector{int}
    W :AbstractArray{float, 2}
    Wx :AbstractArray{float, 2}
    M :Vector{float}
    Me :Vector{float}
    A :Vector{float}
    Ae :Vector{float}
    map :Vector{int}
    bmu :Vector{int}
    n_categories :int
    n_clusters :int



class AdaptiveResonance:

    def DVFA():
        opts = opts_DVFA()
        DVFA(opts)
     # DVFA()

    def DVFA(opts::opts_DVFA):
        DVFA(
            opts,                           # opts
            DataConfig(),                   # config
            Array{int}(undef, 0),       # labels
            Array{float}(undef, 0, 0),    # W
            Array{float}(undef, 0, 0),    # Wx
            Array{float}(undef, 0),       # M
            Array{float}(undef, 0),       # Me
            Array{float}(undef, 0),       # A
            Array{float}(undef, 0),       # Ae
            Array{int}(undef, 0),       # map
            Array{int}(undef, 0),       # bmu
            0,                              # n_categories
            0,                              # n_clusters
        )


    def train(art::DVFA, x; learning=True):
        # Data information and setup
        if ndims(x) > 1:
            n_samples = size(x)[2]
        else:
            n_samples = 1

        x = vcat(x, 1 .- x) # complement code
        if n_samples == 1:
            y_hat = zero(int)
        else:
            y_hat = zeros(int, n_samples)
        # Initialization
        if isempty(art.W):
            # Set the first label as either 1 or the first provided label
            local_label = 1
            # Add the local label to the output vector
            if n_samples == 1:
                y_hat = local_label
            else:
                y_hat[1] = local_label

            # Create a new category and cluster
            art.W = ones(art.config.dim_comp, 1)
            art.Wx = zeros(art.config.dim_comp, 1)
            art.n_categories = 1
            art.n_clusters = 1
            push(art.labels, local_label)
            # Skip the first training entry
            push(art.A, 0.0)
            push(art.Ae, 0.0)
            push(art.bmu, 1)
            skip_first = true
        else:
            skip_first = false

        for i in len(1, n_samples):
            # Skip the first sample if we just initialized
            if (i == 1 and skip_first):
                continue
            # Grab the sample slice
            sample = x[:, i]
            max_bmu = 0.0
            max_bmue = 0.0
            bmu_with_max = -1
            # Compute the activation and match for all categories
            activation_match(art, sample)
            # Sort activation def values in descending order
            index = sortperm(art.M, rev=True)
            # Default to mismatch
            mismatch_flag = True
            label = -1
            # Loop over all categories
            for j in len(1, art.n_categories):
                # Best matching unit, order does not matter
                bmu = index[j]
                # Vigilance test upper bound
                if art.M[bmu] > max_bmu:
                    bmu_with_max = bmu
                    max_bmue = art.Me[bmu]
                    max_bmu = art.M[bmu]

                if !learning:
                    # no learning
                elif art.M[bmu] >= art.opts.rho_ub:
                    # learn with fast commit
                    art.W[:, bmu] = art.Wx[:, bmu]
                    # Update sample label for output`
                    if art.M[bmu] >= max_bmu:
                        label = art.labels[bmu]

                    mismatch_flag = false
                # Vigilance test lower bound
                elif art.M[bmu] >= art.opts.rho_lb and mismatch_flag:
                    if art.M[bmu] >= max_bmu:
                        label = art.labels[bmu]

                    push(art.labels, label)
                    # Fast commit the sample, same as per mismatch
                    art.W = hcat(art.W, sample)
                    art.Wx = hcat(art.W, zeros(art.config.dim_comp, 1))
                    art.n_categories += 1
                    # No mismatch
                    mismatch_flag = false
                    break
                else:
                    break

            push(art.A, max_bmu)
            push(art.Ae, max_bmue)
            push(art.bmu, bmu_with_max)
            # If there was no resonant category, make a new one
            if mismatch_flag and learning:
                label = -1
                push(art.labels, art.n_clusters + 1)
                # Fast commit the sample
                art.W = hcat(art.W, sample)
                art.Wx = hcat(art.W, zeros(art.config.dim_comp, 1))
                # Increment the number of categories and clusters
                art.n_categories += 1
                art.n_clusters += 1

            if n_samples == 1:
                y_hat = label
            else:
                y_hat[i] = label
        return y_hat


    def activation_match(art::DVFA, x::Vector):
        art.M = zeros(art.n_categories)
        art.Me = zeros(art.n_categories)
        ei = length(x)÷2
        for jx in len(1, art.n_categories):
            W = art.W[:, jx]
            em = minimum([x W], dims = 2)
            art.Wx[:, jx] = em #stored because this can be reused in the learning (fast commit)
            numerator = norm(em, 1)
            nW = norm(W, 1)
            if nW == 0:
                nW = 0.001
            feature_similarity = numerator/nW
            eme = [em[ei];em[end]]
            We = [W[ei];W[end]]
            neme = norm(eme, 1)
            nWe = norm(We, 1)
            energy_similarity = neme / nWe
            art.M[jx] = feature_similarity^3 * energy_similarity^2
            art.Me[jx] = energy_similarity
