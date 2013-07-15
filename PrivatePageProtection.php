<?php
/**
 * PrivatePageProtection extension - implements per page acccess restrictions based on user group.
 * Which groups are authorized for viewing is defined on-page, using a parser function.
 *
 * @file
 * @ingroup Extensions
 * @author Daniel Kinzler, brightbyte.de
 * @copyright © 2007 Daniel Kinzler
 * @license GNU General Public Licence 2.0 or later
 */

/*
* WARNING: you can use this extension to deny read access to some pages. Keep in mind that this
* may be circumvented in several ways. This extension doesn't try to
* plug such holes. Also note that pages that are not readable will still be shown in listings,
* such as the search page, categories, etc.
*
* Known ways to access "hidden" pages:
* - transcluding as template. can be avoided using $wgNonincludableNamespaces.
* Some search messages may reveal the page existance by producing links to it (MediaWiki:searchsubtitle,
* MediaWiki:noexactmatch, MediaWiki:searchmenu-exists, MediaWiki:searchmenu-new...).
*
* NOTE: you cannot GRANT access to things forbidden by $wgGroupPermissions. You can only DENY access
* granted there.
*/

if (!defined('MEDIAWIKI')) {
    echo("This file is an extension to the MediaWiki software and cannot be used standalone.\n");
    die(1);
}
$wgExtensionFunctions[] = 'wfSetupPrivatePageProtection';
$wgExtensionCredits['parserfunction'][] = array(
    'path' => __FILE__,
    'name' => 'PrivatePageProtection',
    'author' => array('Daniel Kinzler', 'Denisov Denis'),
    'url' => 'http://mediawiki.org/wiki/Extension:PrivatePageProtection',
    'descriptionmsg' => 'privatepp-desc',
);

$wgExtensionMessagesFiles['PrivatePageProtection'] = dirname(__FILE__) . '/PrivatePageProtection.i18n.php';
$wgExtensionMessagesFiles['PrivatePageProtectionMagic'] = dirname(__FILE__) . '/PrivatePageProtection.i18n.magic.php';


class PrivatePageProtection
{
    static public $denyRecursive;

    function __construct()
    {
        global $wgHooks;

        $wgHooks['getUserPermissionsErrorsExpensive'][] = $this;
        $wgHooks['ParserFirstCallInit'][] = $this;

        $wgHooks['ArticleSave'][] = $this;
    }

    function __toString()
    {
        return __CLASS__;
    }

    function onParserFirstCallInit(&$parser)
    {
        $parser->setFunctionHook('allow-groups', array(__CLASS__, 'privateppRenderTag'));

        return true;
    }

    function ongetUserPermissionsErrorsExpensive($title, $user, $action, &$result)
    {
        $groups = $this->privateppGetAllowedGroups($title);
        $result = $this->privateppGetAccessError($groups, $user);

        if ($result) {
            return false;
        }

        return true;
    }

    function onArticleSave(&$wikipage, &$user, &$text, &$summary, $minor, $watchthis, $sectionanchor, &$flags, &$status)
    {
        $userGroups = $user->getGroups();

        if (!in_array('locker', $userGroups) and !in_array('sysop', $userGroups)) {
            return false;
        }

        $editInfo = $wikipage->prepareTextForEdit($text, null, $user);
        $groups = $editInfo->output->getProperty('ppp_allowed_groups');

        $err = $this->privateppGetAccessError($groups, $user);

        if (!$err) {
            return true;
        }

        $err[0] = 'privatepp-lockout-prevented'; #override message key
        throw new PermissionsError('edit', array($err));
    }

    static public function privateppRenderTag($parser, $param1 = '', $param2 = '')
    {
        $args = func_get_args();
        $out = $parser->getOutput();

        if (count($args) <= 1) {
            return true;
        }

        $groups = array();

        for ($i = 1; $i < count($args); $i++) {
            $param = strtolower(trim($args[$i]));
            if ($param == 'deny-recursive') {
                self::$denyRecursive = true;
                $out->setProperty('ppp_deny_recursive', self::$denyRecursive);
            } else {
                $groups[] = $param;
            }
        }

        $groups = implode("|", $groups);

        $ppp = $out->getProperty('ppp_allowed_groups');
        if ($ppp) {
            $groups = $ppp . '|' . $groups;
        }

        $out->setProperty('ppp_allowed_groups', $groups);

        return array('text' => '', 'ishtml' => true, 'inline' => true);
    }

    /**
     * Returns a list of allowed groups for the given page.
     */
    public function privateppGetAllowedGroups($title)
    {
        $id = $title->getArticleID();
        $dbr = wfGetDB(DB_SLAVE);

        if ($id == 0) {
            return array();
        }

        $Ids = array($id);
        $out = RequestContext::getMain()->getOutput();

        $res = $dbr->select(array('page_props'),
            array('pp_value'),
            array('pp_page' => $Ids, 'pp_propname' => 'ppp_deny_recursive'),
            __METHOD__);

        $denyRecursive = array();
        if ($res !== false) {
            foreach ($res as $row) {
                $denyRecursive[] = $row->pp_value;
            }
        }

        $dbr->freeResult($res);

        $categories = $this->getCategories($out->getTitle());


        if (!empty($denyRecursive)) {
            $categories = array($categories[0]);
        }

        if (!empty($categories)) {
            $res = $dbr->select(array('page'),
                array('page_id', 'page_title'),
                array('page_title' => $categories),
                __METHOD__);

            foreach ($res as $row) {
                if ($row->page_title) {
                    $Ids[$row->page_title] = intval($row->page_id);
                }
            }

            $dbr->freeResult($res);
        }

        $res = $dbr->select(array('page_props'),
            array('pp_value'),
            array('pp_page' => $Ids, 'pp_propname' => 'ppp_allowed_groups'),
            __METHOD__);

        $groups = array();
        if ($res !== false) {
            foreach ($res as $row) {
                $groups[] = $row->pp_value;
            }
        }

        $groups = array_unique($groups);

        #TODO: use object cache?! get from parser cache?!
        return $groups;
    }

    function privateppGetAccessError($groups, $user)
    {
        global $wgLang;

        if (!$groups) {
            return null;
        }

        if (is_string($groups)) {
            $groups = explode('|', $groups);
        }

        $ugroups = $user->getEffectiveGroups(true);

        # Sysop super permissions
        if (in_array('sysop', $ugroups)) {
            $groups[] = 'sysop';
        }

        $match = array_intersect($ugroups, $groups);

        if ($match) {
            # group is allowed - keep processing
            return null;
        } else {
            # group is denied - abort
            $groupLinks = array_map(array('User', 'makeGroupLinkWiki'), $groups);

            $err = array(
                'badaccess-groups',
                $wgLang->commaList($groupLinks),
                count($groups)
            );

            return $err;
        }
    }

    function getCategories(Title $title)
    {
        $structure = $title->getParentCategoryTree();
        $categoriesTree = $this->array_values_recursive($structure);

        $categoriesTree = array_unique($categoriesTree);

        $categories = array();
        foreach ($categoriesTree as $category) {
            if (strpos($category, ':')) {
                $category = explode(':', $category);
                $categories[] = $category[1];
            }
        }

        return $categories;
    }

    function array_values_recursive($array)
    {
        $arrayKeys = array();

        foreach ($array as $key => $value) {
            $arrayKeys[] = $key;
            if (!empty($value)) {
                $arrayKeys = array_merge($arrayKeys, $this->array_values_recursive($value));
            }
        }

        return $arrayKeys;
    }
}

function wfSetupPrivatePageProtection()
{
    global $wgPrivatePageProtection;

    $wgPrivatePageProtection = new PrivatePageProtection;
}