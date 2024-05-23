<div id="toolbar-certman2">
	<a href='?display=certman2' class="btn btn-default"><i class="fa fa-th-list"></i>&nbsp;&nbsp;<?php echo _('Certificate List')?></a>
</div>
<table data-url="ajax.php?module=certman2&command=getJSON&jdata=grid" data-cache="false" data-toggle="table" data-toolbar="#toolbar-certman2" data-search="true" class="table" id="table-all-side">
    <thead>
        <tr>
            <th data-sortable="true" data-field="cid" data-formatter='certman2formatter'><?php echo _('Certificate')?></th>
        </tr>
    </thead>
</table>
<script type="text/javascript">
	function certman2formatter(v,r){
		return '<a href="?display=certman2&action=view&id='+v+'">'+r['basename']+" ("+r['description']+')</a>';
	}
</script>
