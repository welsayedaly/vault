package vault

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func lookupPaths(i *IdentityStore) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "lookup/group$",
			Fields: map[string]*framework.FieldSchema{
				"type": {
					Type:        framework.TypeString,
					Description: "Type of lookup. Current supported values are 'id' and 'name'",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the group.",
				},
				"id": {
					Type:        framework.TypeString,
					Description: "ID of the group.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.pathLookupGroupUpdate,
			},

			HelpSynopsis:    strings.TrimSpace(lookupHelp["lookup-group"][0]),
			HelpDescription: strings.TrimSpace(lookupHelp["lookup-group"][1]),
		},
		{
			Pattern: "lookup/group-alias$",
			Fields: map[string]*framework.FieldSchema{
				"type": {
					Type:        framework.TypeString,
					Description: "Type of lookup. Current supported values are 'id', 'group_id' and 'factors'.",
				},
				"id": {
					Type:        framework.TypeString,
					Description: "ID of the group.",
				},
				"group_id": {
					Type:        framework.TypeString,
					Description: "ID of the group to which the group alias belongs to.",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the group.",
				},
				"mount_accessor": {
					Type:        framework.TypeString,
					Description: "Accessor of the mount to which the group alias belongs to.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.checkPremiumVersion(i.pathLookupGroupAliasUpdate),
			},

			HelpSynopsis:    strings.TrimSpace(lookupHelp["lookup-group-alias"][0]),
			HelpDescription: strings.TrimSpace(lookupHelp["lookup-group-alias"][1]),
		},
	}
}

func (i *IdentityStore) pathLookupGroupUpdate(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	lookupType := d.Get("type").(string)
	if lookupType == "" {
		return logical.ErrorResponse("empty type"), nil
	}

	switch lookupType {
	case "id":
		groupID := d.Get("id").(string)
		if groupID == "" {
			return logical.ErrorResponse("empty ID"), nil
		}
		group, err := i.memDBGroupByID(groupID, false)
		if err != nil {
			return nil, err
		}
		return i.handleGroupReadCommon(group)
	case "name":
		groupName := d.Get("name").(string)
		if groupName == "" {
			return logical.ErrorResponse("empty name"), nil
		}
		group, err := i.memDBGroupByName(groupName, false)
		if err != nil {
			return nil, err
		}
		return i.handleGroupReadCommon(group)
	default:
		return logical.ErrorResponse(fmt.Sprintf("unrecognized type %q", lookupType)), nil
	}

	return nil, nil
}

func (i *IdentityStore) pathLookupGroupAliasUpdate(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	lookupType := d.Get("type").(string)
	if lookupType == "" {
		return logical.ErrorResponse("empty type"), nil
	}

	switch lookupType {
	case "id":
		groupAliasID := d.Get("id").(string)
		if groupAliasID == "" {
			return logical.ErrorResponse("empty ID"), nil
		}

		groupAlias, err := i.memDBAliasByID(groupAliasID, false, true)
		if err != nil {
			return nil, err
		}

		return i.handleAliasReadCommon(groupAlias)

	case "group_id":
		groupID := d.Get("group_id").(string)
		if groupID == "" {
			return logical.ErrorResponse("empty group_id"), nil
		}

		groupAlias, err := i.memDBAliasByParentID(groupID, false, true)
		if err != nil {
			return nil, err
		}

		return i.handleAliasReadCommon(groupAlias)

	case "factors":
		groupAliasName := d.Get("name").(string)
		if groupAliasName == "" {
			return logical.ErrorResponse("empty 'name'"), nil
		}
		mountAccessor := d.Get("mount_accessor").(string)
		if mountAccessor == "" {
			return logical.ErrorResponse("empty 'mount_accessor'"), nil
		}

		groupAlias, err := i.memDBAliasByFactors(mountAccessor, groupAliasName, false, true)
		if err != nil {
			return nil, err
		}

		return i.handleAliasReadCommon(groupAlias)

	default:
		return logical.ErrorResponse(fmt.Sprintf("unrecognized type %q", lookupType)), nil
	}
}

var lookupHelp = map[string][2]string{
	"lookup-group": {
		"Query groups based on types.",
		`Supported types:
		- 'id'
		To query the group by its ID. This requires 'id' parameter to be set.
		- 'name'
		To query the group by its name. This requires 'name' parameter to be set.
		`,
	},
	"lookup-group-alias": {
		"Query group aliases based on types.",
		`Supported types:
		- 'id'
		To query the group alias by its ID. This requires 'id' parameter to be set.
		- 'group_id'
		To query the group alias by the ID of the group it belongs to. This requires the 'group_id' parameter to be set.
		- 'factors'
		To query the group alias using the factors that uniquely identity a group alias; its name and the mount accessor. This requires the 'name' and 'mount_accessor' parameters to be set.
		`,
	},
}
