<?php

/**
 * Nextcloud - user_sql
 *
 * @copyright 2018 Marcin Łojewski <dev@mlojewski.me>
 * @author    Marcin Łojewski <dev@mlojewski.me>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

namespace OCA\UserSQL\Crypto;

use OCP\IL10N;

/**
 * SHA-1 hash implementation.
 *
 * @author Marcin Łojewski <dev@mlojewski.me>
 */
class SimpleMachinesForum extends AbstractAlgorithm
{
    /**
     * The class constructor.
     *
     * @param IL10N $localization The localization service.
     */
    public function __construct(IL10N $localization)
    {
        parent::__construct($localization);
    }

    // Removes special entities from strings.  Compatibility...
    static function un_htmlspecialchars($string)
    {
        static $translation;

        if (!isset($translation))
            $translation = array_flip(get_html_translation_table(HTML_SPECIALCHARS, ENT_QUOTES)) + array('&#039;' => '\'', '&nbsp;' => ' ');

        return strtr($string, $translation);
    }

    public static function smfPasswordHash($providedUsername, $providedPassword)
    {
        return sha1(strtolower($providedUsername) . self::un_htmlspecialchars($providedPassword));
    }


    /**
     * @inheritdoc
     */
    public function getPasswordHash($password, $salt = null)
    {
        return self::smfPasswordHash($salt, $password);
    }

    /**
     * @inheritdoc
     */
    protected function getAlgorithmName()
    {
        return "SimpleMachinesForum 2.0.x (SHA1)";
    }
}
