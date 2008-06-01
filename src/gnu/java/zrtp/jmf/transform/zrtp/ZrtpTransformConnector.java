/**
 * Copyright (C) 2006-2008 Werner Dittmann
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

package gnu.java.zrtp.jmf.transform.zrtp;

import gnu.java.zrtp.jmf.transform.TransformConnector;
import gnu.java.zrtp.jmf.transform.TransformEngine;

import javax.media.rtp.InvalidSessionAddressException;
import javax.media.rtp.SessionAddress;


/**
 * ZRTP specific Transform Connector.
 * 
 * This class just adds ZRTP specific functions.
 * 
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */
public class ZrtpTransformConnector extends TransformConnector {

    public ZrtpTransformConnector(SessionAddress localAddr,
            TransformEngine engine) throws InvalidSessionAddressException {
        super(localAddr, engine);
    }

    public ZRTPTransformEngine getEngine() {
        if (!(engine instanceof ZRTPTransformEngine)) {
            return null;
        }
        return (ZRTPTransformEngine) engine;
    }
}
