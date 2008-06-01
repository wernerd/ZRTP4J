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

package gnu.java.zrtp;


/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */

public class ZrtpSrtpSecrets {

        protected byte[] keyInitiator;
        protected byte[] saltInitiator;
        protected byte[] keyResponder;
        protected byte[] saltResponder;
        protected int initKeyLen;
        protected int initSaltLen;
        protected int respKeyLen;
        protected int respSaltLen;
        protected int srtpAuthTagLen;
        protected ZrtpCallback.Role  role;

        protected ZrtpSrtpSecrets() {
        }

        /**
         * @return the keyInitiator
         */
        public byte[] getKeyInitiator() {
            return keyInitiator;
        }

        /**
         * @param keyInitiator the keyInitiator to set
         */
        public void setKeyInitiator(byte[] keyInitiator) {
            this.keyInitiator = keyInitiator;
        }

        /**
         * @return the keyResponder
         */
        public byte[] getKeyResponder() {
            return keyResponder;
        }

        /**
         * @param keyResponder the keyResponder to set
         */
        public void setKeyResponder(byte[] keyResponder) {
            this.keyResponder = keyResponder;
        }

        /**
         * @return the role
         */
        public ZrtpCallback.Role getRole() {
            return role;
        }

        /**
         * @param role the role to set
         */
        public void setRole(ZrtpCallback.Role role) {
            this.role = role;
        }

        /**
         * @return the saltInitiator
         */
        public byte[] getSaltInitiator() {
            return saltInitiator;
        }

        /**
         * @param saltInitiator the saltInitiator to set
         */
        public void setSaltInitiator(byte[] saltInitiator) {
            this.saltInitiator = saltInitiator;
        }

        /**
         * @return the saltResponder
         */
        public byte[] getSaltResponder() {
            return saltResponder;
        }

        /**
         * @param saltResponder the saltResponder to set
         */
        public void setSaltResponder(byte[] saltResponder) {
            this.saltResponder = saltResponder;
        }

        /**
         * @return the srtpAuthTagLen
         */
        public int getSrtpAuthTagLen() {
            return srtpAuthTagLen;
        }

        /**
         * @param srtpAuthTagLen the srtpAuthTagLen to set
         */
        public void setSrtpAuthTagLen(int srtpAuthTagLen) {
            this.srtpAuthTagLen = srtpAuthTagLen;
        }

        /**
         * @return the initKeyLen
         */
        public int getInitKeyLen() {
            return initKeyLen;
        }

        /**
         * @param initKeyLen the initKeyLen to set
         */
        public void setInitKeyLen(int initKeyLen) {
            this.initKeyLen = initKeyLen;
        }

        /**
         * @return the initSaltLen
         */
        public int getInitSaltLen() {
            return initSaltLen;
        }

        /**
         * @param initSaltLen the initSaltLen to set
         */
        public void setInitSaltLen(int initSaltLen) {
            this.initSaltLen = initSaltLen;
        }

        /**
         * @return the respKeyLen
         */
        public int getRespKeyLen() {
            return respKeyLen;
        }

        /**
         * @param respKeyLen the respKeyLen to set
         */
        public void setRespKeyLen(int respKeyLen) {
            this.respKeyLen = respKeyLen;
        }

        /**
         * @return the respSaltLen
         */
        public int getRespSaltLen() {
            return respSaltLen;
        }

        /**
         * @param respSaltLen the respSaltLen to set
         */
        public void setRespSaltLen(int respSaltLen) {
            this.respSaltLen = respSaltLen;
        }

}
