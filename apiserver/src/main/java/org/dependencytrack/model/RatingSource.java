/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

/**
 * Defines the source of a rating (CVSS or OWASP) in an analysis.
 * This enum is used to track the origin of ratings and enforce precedence rules
 * to prevent unintended overwrites.
 *
 * <p>Precedence order (highest to lowest):</p>
 * <ol>
 *   <li>{@link #MANUAL} - User-provided rating that overrides all other sources</li>
 *   <li>{@link #VEX} - Rating from VEX (Vulnerability Exploitability eXchange) documents</li>
 *   <li>{@link #POLICY} - Rating applied by organizational policies</li>
 *   <li>{@link #NVD} - Default rating from the National Vulnerability Database</li>
 * </ol>
 *
 * @since 5.8.0
 */
public enum RatingSource {

    /**
     * Rating manually set by a security analyst or user.
     * This has the highest precedence and can only be overwritten by another MANUAL rating.
     */
    MANUAL(4),

    /**
     * Rating imported from a VEX (Vulnerability Exploitability eXchange) document.
     * VEX ratings are context-specific and reflect the actual risk in a particular environment.
     * Can overwrite POLICY and NVD ratings, but not MANUAL ratings.
     */
    VEX(3),

    /**
     * Rating applied by an organizational policy.
     * Can overwrite NVD ratings, but not MANUAL or VEX ratings.
     */
    POLICY(2),

    /**
     * Default rating from the National Vulnerability Database (NVD) or other vulnerability sources.
     * This has the lowest precedence and can be overwritten by any other source.
     */
    NVD(1);

    private final int precedence;

    RatingSource(int precedence) {
        this.precedence = precedence;
    }

    /**
     * Returns the precedence level of this rating source.
     * Higher values indicate higher precedence.
     *
     * @return the precedence level
     */
    public int getPrecedence() {
        return precedence;
    }

    /**
     * Determines if this rating source can overwrite another rating source.
     *
     * @param other the rating source to compare against
     * @return true if this source can overwrite the other source
     */
    public boolean canOverwrite(RatingSource other) {
        if (other == null) {
            return true;
        }
        return this.precedence >= other.precedence;
    }
}
